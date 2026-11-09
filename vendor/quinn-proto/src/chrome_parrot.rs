//! Xray-core's ChromeParrot client handshake
//!
//! Xray-core v26.10.31 dials Hysteria and HTTP/3 over the apernet fork of
//! quic-go (v0.61.1-0.20260806010916-184d081eef3e) with its `ChromeParrot`
//! option on unless `quicParams.disableChromeParrot` is set. That option shapes
//! a client's handshake like Google Chrome's. This module holds the pieces of it
//! that live below TLS, each a port of the fork's code:
//!
//! - [`GoPcg`]: Go's `math/rand/v2` PCG, which seeds per connection the packet
//!   packer's randomness (`packet_packer.go`).
//! - [`crypto_split`]: how a ClientHello too large for one Initial is laid out:
//!   the first packet carries its head and its tail (`chromeCryptoSplit`).
//! - [`chaos_payload`]: the chaos protection of an Initial packet: CRYPTO
//!   frames cut at random, PINGs and padding runs mixed in and the lot
//!   shuffled, in the same number of bytes (`packet_packer_chaos.go`).
//! - [`packet_number_len`]: the packet number length rule
//!   (`PacketNumberLengthForHeaderChrome`).
//! - [`write_transport_parameters`]: the transport parameters encoded the way
//!   Chrome encodes them (`transport_parameters_chrome.go`).
//!
//! Every draw happens in the order the fork makes it, from the same kind of
//! source, so a test that hands both the same seed and bytes gets the same
//! packets.

use bytes::{BufMut, Bytes};

use crate::{
    coding::BufMutExt,
    config::{EndpointConfig, TransportConfig},
    shared::ConnectionId,
    transport_parameters::{TransportParameterId, TransportParameters},
    VarInt,
};

/// QUIC version 1
const VERSION_1: u32 = 0x0000_0001;

/// `google_connection_options`, which carries four-character option tags
const GOOGLE_CONNECTION_OPTIONS: u64 = 0x3128;
/// The sole option tag Chrome sends in `google_connection_options`
const CHROME_CONNECTION_OPTIONS: &[u8; 4] = b"ORIG";
/// `version_information`, RFC 9368
const VERSION_INFORMATION: u64 = 0x11;
/// The GREASE transport parameter's value is 0..=15 random bytes.
const GREASE_MAX_VALUE_LEN: u64 = 15;

/// How many extra CRYPTO frames to attempt (`chaosMinAddedCryptoFrames`,
/// `chaosMaxAddedCryptoFrames`)
const CHAOS_MIN_ADDED_CRYPTO_FRAMES: usize = 2;
const CHAOS_MAX_ADDED_CRYPTO_FRAMES: usize = 10;
/// How many PING frames to mix in
const CHAOS_MIN_PING_FRAMES: usize = 2;
const CHAOS_MAX_PING_FRAMES: usize = 10;
/// The leading CRYPTO frame of a split ClientHello is 55..=86 bytes long.
const CHAOS_MIN_FIRST_FRAME_LEN: u64 = 55;
const CHAOS_FIRST_FRAME_LEN_RANDOM: usize = 32;

/// The least room left in a datagram that still sizes the next packet number
/// (`minDatagramRoomForSizing`)
pub(crate) const MIN_DATAGRAM_ROOM_FOR_SIZING: u64 = 40;

/// Go's `math/rand/v2` PCG generator with its DXSM output, and the
/// `Rand.IntN` and `Rand.Shuffle` the packet packer draws through, as a
/// 64-bit Go build runs them
#[derive(Clone, Debug)]
pub(crate) struct GoPcg {
    hi: u64,
    lo: u64,
}

impl GoPcg {
    /// `rand.NewPCG` with the two big-endian halves of 16 seed bytes, as
    /// `newPacketPacker` seeds it from `crypto/rand`
    pub(crate) fn new(seed: [u8; 16]) -> Self {
        let mut hi = [0; 8];
        let mut lo = [0; 8];
        hi.copy_from_slice(&seed[..8]);
        lo.copy_from_slice(&seed[8..]);
        Self {
            hi: u64::from_be_bytes(hi),
            lo: u64::from_be_bytes(lo),
        }
    }

    /// A generator seeded from the system's randomness
    pub(crate) fn from_entropy() -> Self {
        let mut seed = [0; 16];
        fill_random(&mut seed);
        Self::new(seed)
    }

    fn next(&mut self) -> (u64, u64) {
        const MUL_HI: u64 = 2549297995355413924;
        const MUL_LO: u64 = 4865540595714422341;
        const INC_HI: u64 = 6364136223846793005;
        const INC_LO: u64 = 1442695040888963407;
        // state = state * mul + inc, in 128 bits
        let product = u128::from(self.lo) * u128::from(MUL_LO);
        let mut hi = (product >> 64) as u64;
        let lo = product as u64;
        hi = hi
            .wrapping_add(self.hi.wrapping_mul(MUL_LO))
            .wrapping_add(self.lo.wrapping_mul(MUL_HI));
        let (lo, carry) = lo.overflowing_add(INC_LO);
        let hi = hi.wrapping_add(INC_HI).wrapping_add(u64::from(carry));
        self.lo = lo;
        self.hi = hi;
        (hi, lo)
    }

    /// `PCG.Uint64`
    pub(crate) fn uint64(&mut self) -> u64 {
        const CHEAP_MUL: u64 = 0xda94_2042_e4dd_58b5;
        let (mut hi, lo) = self.next();
        hi ^= hi >> 32;
        hi = hi.wrapping_mul(CHEAP_MUL);
        hi ^= hi >> 48;
        hi.wrapping_mul(lo | 1)
    }

    /// `Rand.uint64n`, Lemire's method
    fn uint64n(&mut self, n: u64) -> u64 {
        if n & (n - 1) == 0 {
            return self.uint64() & (n - 1);
        }
        let mut product = u128::from(self.uint64()) * u128::from(n);
        if (product as u64) < n {
            let threshold = n.wrapping_neg() % n;
            while (product as u64) < threshold {
                product = u128::from(self.uint64()) * u128::from(n);
            }
        }
        (product >> 64) as u64
    }

    /// `Rand.IntN`
    pub(crate) fn int_n(&mut self, n: usize) -> usize {
        assert!(n > 0, "invalid argument to IntN");
        self.uint64n(n as u64) as usize
    }

    /// `Rand.Shuffle`, a Fisher-Yates shuffle
    pub(crate) fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.uint64n(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}

/// Fills `out` from the thread's cryptographically secure generator, as the
/// fork reads `crypto/rand`
pub(crate) fn fill_random(out: &mut [u8]) {
    use rand::Rng;
    rand::rng().fill_bytes(out);
}

fn varint_len(value: u64) -> u64 {
    VarInt::from_u64(value).map_or(8, |v| v.size() as u64)
}

/// `cryptoFrameHeaderLen`: a CRYPTO frame header's size for an offset and a
/// data length
pub(crate) fn crypto_frame_header_len(offset: u64, len: u64) -> u64 {
    1 + varint_len(offset) + varint_len(len)
}

/// `chromeCryptoSplit`: for `pending` bytes of a ClientHello queued at
/// `offset`, with `available` bytes of payload room in a packet, returns the
/// lengths of the leading and the trailing frame the first packet carries
/// together, or `None` when the data fits in one packet.
///
/// It draws from `rng` once, and only once it has decided to split, as the
/// fork does.
pub(crate) fn crypto_split(
    pending: u64,
    offset: u64,
    available: u64,
    rng: &mut GoPcg,
) -> Option<(u64, u64)> {
    if pending == 0 || available == 0 {
        return None;
    }
    let min_frame = crypto_frame_header_len(offset + pending - 1, pending);
    if available < 2 * min_frame {
        return None;
    }
    // The first packet holds two frames, later packets one.
    let max_first = available - 2 * min_frame;
    let max_other = available - min_frame;
    if pending <= max_first {
        return None;
    }
    let occupied = max_other - max_first;
    let packets = (pending + occupied + max_other - 1) / max_other;
    let data_other = (pending + occupied + packets - 1) / packets;
    if data_other < occupied {
        return None;
    }
    let data_first = data_other - occupied;
    let first = CHAOS_MIN_FIRST_FRAME_LEN + rng.int_n(CHAOS_FIRST_FRAME_LEN_RANDOM) as u64;
    if pending <= first || data_first <= first {
        return None;
    }
    Some((first, data_first - first))
}

/// A CRYPTO frame's offset and data
pub(crate) type CryptoPiece = (u64, Bytes);

enum ChaosItem {
    Crypto(CryptoPiece),
    Other(Vec<u8>),
    Ping,
    Padding(u64),
}

/// `appendChaosProtectedPayload`: writes an Initial packet's payload as
/// Chromium's chaos protector does, in exactly `ack`, `crypto` and `others`
/// plus `padding` bytes.
///
/// The ACK, already encoded, goes first and stays out of the shuffle. The
/// CRYPTO frames are cut a bounded number of times, PINGs are added and the
/// padding is split into runs; every byte the extra frame headers and PINGs
/// take comes out of the padding. `others` are other frames, encoded.
pub(crate) fn chaos_payload(
    out: &mut Vec<u8>,
    ack: Option<&[u8]>,
    crypto: Vec<CryptoPiece>,
    others: Vec<Vec<u8>>,
    padding: u64,
    rng: &mut GoPcg,
) {
    if let Some(ack) = ack {
        out.extend_from_slice(ack);
    }
    let (crypto, mut budget) = shred_crypto(crypto, others.len(), padding, rng);
    let mut items = Vec::with_capacity(crypto.len() + others.len() + 2 * CHAOS_MAX_PING_FRAMES);
    items.extend(crypto.into_iter().map(ChaosItem::Crypto));
    items.extend(others.into_iter().map(ChaosItem::Other));
    let pings = ((CHAOS_MIN_PING_FRAMES
        + rng.int_n(CHAOS_MAX_PING_FRAMES - CHAOS_MIN_PING_FRAMES + 1)) as u64)
        .min(budget);
    items.extend((0..pings).map(|_| ChaosItem::Ping));
    budget -= pings;
    let runs = spread_padding(items.len(), budget, rng);
    items.extend(runs.into_iter().map(ChaosItem::Padding));
    rng.shuffle(&mut items);
    for item in items {
        match item {
            ChaosItem::Crypto((offset, data)) => {
                out.write_var(0x06);
                out.write_var(offset);
                out.write_var(data.len() as u64);
                out.put_slice(&data);
            }
            ChaosItem::Other(frame) => out.extend_from_slice(&frame),
            ChaosItem::Ping => out.push(0x01),
            ChaosItem::Padding(len) => out.resize(out.len() + len as usize, 0),
        }
    }
}

/// `shredCryptoFrames`: a bounded number of attempts to split a frame chosen
/// among all of the packet's frames, so an attempt that lands on another frame
/// is spent. Returns the frames and the padding left.
fn shred_crypto(
    mut crypto: Vec<CryptoPiece>,
    others: usize,
    mut budget: u64,
    rng: &mut GoPcg,
) -> (Vec<CryptoPiece>, u64) {
    if crypto.is_empty() {
        return (crypto, budget);
    }
    let mut lo = crypto[0].0;
    let mut hi = 0;
    for (offset, data) in &crypto {
        lo = lo.min(*offset);
        hi = hi.max(offset + data.len() as u64);
    }
    let max_overhead = crypto_frame_header_len(hi, hi - lo);
    let attempts = CHAOS_MIN_ADDED_CRYPTO_FRAMES
        + rng.int_n(CHAOS_MAX_ADDED_CRYPTO_FRAMES - CHAOS_MIN_ADDED_CRYPTO_FRAMES + 1);
    for _ in 0..attempts {
        if budget < max_overhead {
            break;
        }
        let index = rng.int_n(crypto.len() + others);
        if index >= crypto.len() {
            continue;
        }
        let (offset, data) = crypto[index].clone();
        if data.len() <= 1 {
            continue;
        }
        let cut = 1 + rng.int_n(data.len() - 1);
        let first = (offset, data.slice(..cut));
        let second = (offset + cut as u64, data.slice(cut..));
        budget += crypto_frame_header_len(offset, data.len() as u64);
        budget -= crypto_frame_header_len(first.0, first.1.len() as u64);
        budget -= crypto_frame_header_len(second.0, second.1.len() as u64);
        crypto[index] = first;
        crypto.push(second);
    }
    (crypto, budget)
}

/// `spreadPadding`: each of `frames` positions takes a uniform share of what
/// is left; any remainder is a last run.
fn spread_padding(frames: usize, mut budget: u64, rng: &mut GoPcg) -> Vec<u64> {
    let mut runs = Vec::with_capacity(frames + 1);
    if budget == 0 {
        return runs;
    }
    for _ in 0..frames {
        if budget == 0 {
            break;
        }
        let n = rng.int_n(budget as usize + 1) as u64;
        if n == 0 {
            continue;
        }
        runs.push(n);
        budget -= n;
    }
    if budget > 0 {
        runs.push(budget);
    }
    runs
}

/// `PacketNumberLengthForHeaderChrome`: the larger of the unacknowledged range
/// and the congestion window in packets, quadrupled, sets the shortest length
/// that encodes it: one, two or four bytes, never three.
pub(crate) fn packet_number_len(pn: u64, largest_acked: Option<u64>, cwnd_packets: u64) -> usize {
    let unacked = match largest_acked {
        None => pn + 1,
        Some(largest) => pn.saturating_sub(largest),
    };
    let delta = unacked.max(cwnd_packets);
    if delta < (1 << 8) / 4 {
        1
    } else if delta < (1 << 16) / 4 {
        2
    } else {
        4
    }
}

/// `randUint64n`: eight big-endian random bytes modulo `n`
fn random_below(n: u64, random: &mut dyn FnMut(&mut [u8])) -> u64 {
    let mut buf = [0; 8];
    random(&mut buf);
    u64::from_be_bytes(buf) % n
}

/// `marshalChrome`: a client's transport parameters as Chrome encodes them.
///
/// Thirteen parameters, each encoded on its own and then shuffled: the
/// integer limits, `initial_source_connection_id`, `version_information`
/// (QUIC v1, then v1 and a GREASE version in random order),
/// `max_datagram_frame_size` when datagrams are on,
/// `google_connection_options` ("ORIG") and a GREASE parameter with an 8-byte
/// identifier and 0..=15 random bytes. `ack_delay_exponent`, `max_ack_delay`,
/// `disable_active_migration` and `active_connection_id_limit` are left out,
/// so the peer assumes their defaults. Every random byte is read from
/// `random`, in the fork's order.
pub(crate) fn write_transport_parameters<W: BufMut>(
    params: &TransportParameters,
    w: &mut W,
    random: &mut dyn FnMut(&mut [u8]),
) {
    let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(13);
    let varint_param = |id: TransportParameterId, value: VarInt| {
        let mut b = Vec::new();
        b.write_var(id as u64);
        b.write_var(value.size() as u64);
        b.write(value);
        b
    };
    encoded.push(varint_param(
        TransportParameterId::MaxIdleTimeout,
        params.max_idle_timeout,
    ));
    encoded.push(varint_param(
        TransportParameterId::MaxUdpPayloadSize,
        params.max_udp_payload_size,
    ));
    encoded.push(varint_param(
        TransportParameterId::InitialMaxData,
        params.initial_max_data,
    ));
    encoded.push(varint_param(
        TransportParameterId::InitialMaxStreamDataBidiLocal,
        params.initial_max_stream_data_bidi_local,
    ));
    encoded.push(varint_param(
        TransportParameterId::InitialMaxStreamDataBidiRemote,
        params.initial_max_stream_data_bidi_remote,
    ));
    encoded.push(varint_param(
        TransportParameterId::InitialMaxStreamDataUni,
        params.initial_max_stream_data_uni,
    ));
    encoded.push(varint_param(
        TransportParameterId::InitialMaxStreamsBidi,
        params.initial_max_streams_bidi,
    ));
    encoded.push(varint_param(
        TransportParameterId::InitialMaxStreamsUni,
        params.initial_max_streams_uni,
    ));

    let mut cid = Vec::new();
    cid.write_var(TransportParameterId::InitialSourceConnectionId as u64);
    let initial_src_cid = params.initial_src_cid.as_deref().unwrap_or(&[]);
    cid.write_var(initial_src_cid.len() as u64);
    cid.put_slice(initial_src_cid);
    encoded.push(cid);

    encoded.push(version_information(random));

    if let Some(size) = params.max_datagram_frame_size {
        encoded.push(varint_param(TransportParameterId::MaxDatagramFrameSize, size));
    }

    let mut options = Vec::new();
    options.write_var(GOOGLE_CONNECTION_OPTIONS);
    options.write_var(CHROME_CONNECTION_OPTIONS.len() as u64);
    options.put_slice(CHROME_CONNECTION_OPTIONS);
    encoded.push(options);

    encoded.push(grease_parameter(random));

    for i in (1..encoded.len()).rev() {
        let j = random_below(i as u64 + 1, random) as usize;
        encoded.swap(i, j);
    }
    for param in encoded {
        w.put_slice(&param);
    }
}

/// The transport parameters a ChromeParrot client built from `config` and
/// `endpoint_config` sends, with `initial_src_cid` and every random byte read
/// from `random`, in quic-go's order. For deterministic tests against quic-go.
#[doc(hidden)]
pub fn chrome_parrot_transport_parameters(
    config: &TransportConfig,
    endpoint_config: &EndpointConfig,
    initial_src_cid: &[u8],
    random: &mut dyn FnMut(&mut [u8]),
) -> Vec<u8> {
    let params = TransportParameters::chrome_parrot(
        config,
        endpoint_config,
        ConnectionId::new(initial_src_cid),
    );
    let mut out = Vec::new();
    write_transport_parameters(&params, &mut out, random);
    out
}

/// `marshalChromeVersionInformation`: chosen version 1, then version 1 and a
/// GREASE version in random order
fn version_information(random: &mut dyn FnMut(&mut [u8])) -> Vec<u8> {
    let mut b = Vec::new();
    b.write_var(VERSION_INFORMATION);
    b.write_var(12);
    b.put_u32(VERSION_1);
    let mut available = [VERSION_1, grease_version(random)];
    if random_below(2, random) == 1 {
        available.swap(0, 1);
    }
    for version in available {
        b.put_u32(version);
    }
    b
}

/// `greaseQUICVersion`: a reserved version of the form 0x?a?a?a?a
fn grease_version(random: &mut dyn FnMut(&mut [u8])) -> u32 {
    let mut buf = [0; 4];
    random(&mut buf);
    for byte in &mut buf {
        *byte = (*byte & 0xf0) | 0x0a;
    }
    u32::from_be_bytes(buf)
}

/// `marshalChromeGREASE`: a reserved identifier 31 * N + 27 that fills an
/// 8-byte varint, and 0..=15 random bytes
fn grease_parameter(random: &mut dyn FnMut(&mut [u8])) -> Vec<u8> {
    const N_MIN: u64 = ((1 << 30) - 27 + 30) / 31;
    const N_MAX: u64 = ((1 << 62) - 1 - 27) / 31;
    let n = N_MIN + random_below(N_MAX - N_MIN, random);
    let mut b = Vec::new();
    b.write_var(31 * n + 27);
    let len = random_below(GREASE_MAX_VALUE_LEN + 1, random);
    b.write_var(len);
    let mut value = vec![0; len as usize];
    // Go's `rand.Read` of nothing reads nothing.
    if len > 0 {
        random(&mut value);
    }
    b.put_slice(&value);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `math/rand/v2` with `rand.NewPCG(1, 2)`: `Uint64()` four times, then
    /// `IntN(10)` and `IntN(1000)`, as Go 1.27 prints them
    #[test]
    fn pcg_matches_go() {
        let mut seed = [0; 16];
        seed[7] = 1;
        seed[15] = 2;
        let mut rng = GoPcg::new(seed);
        assert_eq!(
            [rng.uint64(), rng.uint64(), rng.uint64(), rng.uint64()],
            GO_PCG_1_2_UINT64
        );
        assert_eq!([rng.int_n(10), rng.int_n(1000)], GO_PCG_1_2_INTN);
    }

    // Generated with Go 1.27.3:
    //   r := rand.New(rand.NewPCG(1, 2))
    //   fmt.Println(r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64(), r.IntN(10), r.IntN(1000))
    const GO_PCG_1_2_UINT64: [u64; 4] = [
        14192431797130687760,
        11371241257079532652,
        14470142590855381128,
        14694613213362438554,
    ];
    const GO_PCG_1_2_INTN: [usize; 2] = [2, 41];

    #[test]
    fn shuffle_is_fisher_yates_over_uint64n() {
        let mut seed = [0; 16];
        seed[0] = 9;
        let mut a = GoPcg::new(seed);
        let mut b = a.clone();
        let mut items: Vec<u32> = (0..13).collect();
        a.shuffle(&mut items);
        let mut expected: Vec<u32> = (0..13).collect();
        for i in (1..expected.len()).rev() {
            let j = b.int_n(i + 1);
            expected.swap(i, j);
        }
        assert_eq!(items, expected);
    }

    #[test]
    fn packet_number_len_never_picks_three_bytes() {
        assert_eq!(packet_number_len(1, None, 32), 1);
        assert_eq!(packet_number_len(2, None, 136), 2);
        assert_eq!(packet_number_len(0, None, 63), 1);
        assert_eq!(packet_number_len(0, None, 64), 2);
        assert_eq!(packet_number_len(100_000, Some(10), 0), 4);
        assert_eq!(packet_number_len(16_383, None, 0), 4);
        assert_eq!(packet_number_len(16_382, None, 0), 2);
        assert_eq!(packet_number_len(5, Some(4), 0), 1);
    }

    #[test]
    fn crypto_split_keeps_the_first_packet_within_its_room() {
        for pending in [1_000u64, 1_802, 1_830, 2_400, 3_000] {
            for seed in 0..32u8 {
                let mut rng = GoPcg::new([seed; 16]);
                let Some((first, last)) = crypto_split(pending, 0, 1_215, &mut rng) else {
                    continue;
                };
                assert!((55..=86).contains(&first));
                let head = crypto_frame_header_len(0, first) + first;
                let tail = crypto_frame_header_len(pending - last, last) + last;
                assert!(head + tail <= 1_215, "{pending} {first} {last}");
            }
        }
        let mut rng = GoPcg::new([0; 16]);
        assert_eq!(crypto_split(900, 0, 1_215, &mut rng), None);
    }

    /// quic-go cuts while the padding left covers a frame header: a budget of
    /// exactly one header still pays for a cut.
    #[test]
    fn a_budget_of_exactly_one_header_still_cuts() {
        let data = Bytes::from(vec![0x16; 900]);
        let header = crypto_frame_header_len(900, 900);
        for seed in 0..16u8 {
            let mut rng = GoPcg::new([seed; 16]);
            let (crypto, budget) = shred_crypto(vec![(0, data.clone())], 0, header, &mut rng);
            assert!(crypto.len() >= 2, "seed {seed}");
            let written: u64 = crypto
                .iter()
                .map(|(o, d)| crypto_frame_header_len(*o, d.len() as u64) + d.len() as u64)
                .sum();
            assert_eq!(written + budget, crypto_frame_header_len(0, 900) + 900 + header, "seed {seed}");
        }
    }

    /// The ACK stays out of the shuffle, in front.
    #[test]
    fn chaos_writes_the_ack_first() {
        let ack = [0x02, 0x05, 0x00, 0x00, 0x03];
        for seed in 0..32u8 {
            let mut rng = GoPcg::new([seed; 16]);
            let mut out = Vec::new();
            let data = Bytes::from(vec![0x16; 400]);
            chaos_payload(&mut out, Some(&ack), vec![(0, data)], Vec::new(), 200, &mut rng);
            assert_eq!(out[..ack.len()], ack);
            assert_eq!(out.len(), ack.len() + 1 + 1 + 2 + 400 + 200);
        }
    }

    #[test]
    fn chaos_keeps_the_payload_size_and_the_crypto_bytes() {
        let data: Vec<u8> = (0..900u32).map(|i| i as u8).collect();
        let data = Bytes::from(data);
        for seed in 0..64u8 {
            let mut rng = GoPcg::new([seed; 16]);
            let mut out = Vec::new();
            let pieces = vec![(0, data.slice(..70)), (980, data.slice(70..))];
            let frames: u64 = pieces
                .iter()
                .map(|(o, d)| crypto_frame_header_len(*o, d.len() as u64) + d.len() as u64)
                .sum();
            chaos_payload(&mut out, None, pieces, Vec::new(), 300, &mut rng);
            assert_eq!(out.len() as u64, frames + 300);
            let mut covered = vec![false; 900];
            let mut p = 0;
            while p < out.len() {
                match out[p] {
                    0x00 | 0x01 => p += 1,
                    0x06 => {
                        let mut r = &out[p + 1..];
                        let start = r.len();
                        let offset = crate::coding::BufExt::get_var(&mut r).unwrap();
                        let len = crate::coding::BufExt::get_var(&mut r).unwrap() as usize;
                        let header = start - r.len();
                        let index = if offset >= 980 { offset - 980 + 70 } else { offset } as usize;
                        assert_eq!(&r[..len], &data[index..index + len]);
                        covered[index..index + len].iter_mut().for_each(|c| *c = true);
                        p += 1 + header + len;
                    }
                    other => panic!("unexpected frame type {other:#x}"),
                }
            }
            assert!(covered.iter().all(|c| *c));
        }
    }
}
