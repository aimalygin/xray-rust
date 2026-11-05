use std::net::IpAddr;

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use xray_config::{InboundSniffingConfig, SniffingDestination};
use xray_routing::{Target, TargetAddr};
use zeroize::Zeroize;

const QUIC_V1: u32 = 1;
const QUIC_V2: u32 = 0x6b33_43cf;
const QUIC_DRAFT_29: u32 = 0xff00_001d;
// RFC 9369 sections 3.1–3.3.
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
// draft-ietf-quic-tls-29 section 5.2, still sniffed by Xray-core.
const QUIC_DRAFT_29_INITIAL_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];
const QUIC_CLIENT_INITIAL_SECRET_LEN: usize = 32;
const QUIC_INITIAL_KEY_LEN: usize = 16;
const QUIC_INITIAL_IV_LEN: usize = 12;
const QUIC_INITIAL_HP_LEN: usize = 16;
const QUIC_TAG_LEN: usize = 16;
const QUIC_HP_SAMPLE_LEN: usize = 16;
/// Xray-core reassembles at most 32767 bytes of Initial CRYPTO data.
pub(crate) const QUIC_MAX_CRYPTO_STREAM_SIZE: usize = 32_767;
/// Chrome scatters a ClientHello over a handful of CRYPTO frames; more
/// disjoint pieces than this are not a client hello worth waiting for.
const QUIC_MAX_CRYPTO_RANGES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SniffedTarget {
    pub route_target: Target,
    pub dial_target: Target,
    pub protocol: SniffingDestination,
}

pub(crate) fn should_sniff_tcp(config: Option<&InboundSniffingConfig>) -> bool {
    let Some(config) = config else {
        return false;
    };
    config.enabled
        && !config.metadata_only
        && config.dest_override.iter().any(|override_kind| {
            matches!(
                override_kind,
                SniffingDestination::Http | SniffingDestination::Tls
            )
        })
}

pub(crate) fn should_sniff_udp(config: Option<&InboundSniffingConfig>) -> bool {
    let Some(config) = config else {
        return false;
    };
    config.enabled
        && !config.metadata_only
        && config
            .dest_override
            .iter()
            .any(|override_kind| matches!(override_kind, SniffingDestination::Quic))
}

pub(crate) fn sniff_tcp_initial_payload(
    config: &InboundSniffingConfig,
    original: &Target,
    payload: &[u8],
) -> Option<SniffedTarget> {
    if config.metadata_only || payload.is_empty() {
        return None;
    }

    for override_kind in &config.dest_override {
        let domain = match override_kind {
            SniffingDestination::Http => sniff_http_host(payload),
            SniffingDestination::Tls => sniff_tls_client_hello_sni(payload),
            SniffingDestination::Quic => None,
        };
        if let Some(domain) = domain {
            return sniffed_target(config, original, domain, *override_kind);
        }
    }

    None
}

/// What sniffing the first datagrams of a UDP flow has established.
#[derive(Debug)]
pub(crate) enum UdpSniffProgress {
    /// Sniffing is over: the sniffed target, or `None` to keep the original.
    Done(Option<SniffedTarget>),
    /// A QUIC Initial matched, but its ClientHello continues in a later
    /// datagram.
    NeedMore,
}

/// Sniffs the leading datagrams of one UDP flow.
///
/// A ClientHello larger than one datagram, such as Chrome's with a
/// post-quantum key share, arrives in several Initial packets. Xray-core
/// reassembles their CRYPTO data across datagrams, and so does this; only HTTP
/// and TLS are TCP-only sniffers, so QUIC is the one UDP protocol.
pub(crate) struct UdpSniffer<'a> {
    config: &'a InboundSniffingConfig,
    original: &'a Target,
    quic: QuicCryptoAssembler,
}

impl<'a> UdpSniffer<'a> {
    pub(crate) fn new(config: &'a InboundSniffingConfig, original: &'a Target) -> Self {
        Self {
            config,
            original,
            quic: QuicCryptoAssembler::default(),
        }
    }

    /// Feeds the flow's next datagram, starting with its first.
    pub(crate) fn feed(&mut self, datagram: &[u8]) -> UdpSniffProgress {
        if self.config.metadata_only
            || datagram.is_empty()
            || !self
                .config
                .dest_override
                .contains(&SniffingDestination::Quic)
        {
            return UdpSniffProgress::Done(None);
        }
        match self.quic.feed(datagram) {
            QuicSniff::Domain(domain) => UdpSniffProgress::Done(sniffed_target(
                self.config,
                self.original,
                domain,
                SniffingDestination::Quic,
            )),
            QuicSniff::NeedMore => UdpSniffProgress::NeedMore,
            QuicSniff::NoDomain => UdpSniffProgress::Done(None),
        }
    }
}

/// The target a sniffed `domain` makes of `original`, or `None` when
/// `domainsExcluded` or `ipsExcluded` keeps `original`.
fn sniffed_target(
    config: &InboundSniffingConfig,
    original: &Target,
    domain: String,
    protocol: SniffingDestination,
) -> Option<SniffedTarget> {
    let original_ip = match original.addr {
        TargetAddr::Ip(ip) => Some(ip),
        TargetAddr::Domain(_) => None,
    };
    if config.excludes(original_ip, &domain) {
        return None;
    }
    let route_target = Target::new(TargetAddr::Domain(domain), original.port, original.network);
    let dial_target = if config.route_only {
        original.clone()
    } else {
        route_target.clone()
    };
    Some(SniffedTarget {
        route_target,
        dial_target,
        protocol,
    })
}

fn sniff_http_host(payload: &[u8]) -> Option<String> {
    let header_end = find_subslice(payload, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&payload[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    if !is_http_request_line(request_line) {
        return None;
    }

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            return normalize_host(value.trim());
        }
    }

    None
}

fn is_http_request_line(line: &str) -> bool {
    let mut parts = line.split_ascii_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(_) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && matches!(
            method,
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
        )
        && version.starts_with("HTTP/")
}

fn sniff_tls_client_hello_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 9 || payload[0] != 22 {
        return None;
    }
    let record_len = read_u16(payload, 3)? as usize;
    if payload.len() < 5 + record_len {
        return None;
    }
    sniff_tls_client_hello_handshake_sni(&payload[5..5 + record_len])
}

fn sniff_tls_client_hello_handshake_sni(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 4 || handshake[0] != 1 {
        return None;
    }
    let handshake_len = read_u24(handshake, 1)? as usize;
    let body_start = 4usize;
    let body_end = body_start.checked_add(handshake_len)?;
    if body_end > handshake.len() {
        return None;
    }
    sniff_tls_client_hello_body_sni(&handshake[body_start..body_end])
}

fn sniff_tls_client_hello_body_sni(body: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    offset = offset.checked_add(2 + 32)?;
    let session_id_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + session_id_len)?;
    let cipher_suites_len = read_u16(body, offset)? as usize;
    offset = offset.checked_add(2 + cipher_suites_len)?;
    let compression_methods_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + compression_methods_len)?;
    let extensions_len = read_u16(body, offset)? as usize;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }

    while offset + 4 <= extensions_end {
        let extension_type = read_u16(body, offset)?;
        let extension_len = read_u16(body, offset + 2)? as usize;
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        if extension_type == 0 {
            return parse_tls_sni_extension(&body[offset..extension_end]);
        }
        offset = extension_end;
    }

    None
}

/// The SNI of a ClientHello that fits in one datagram.
#[cfg(test)]
fn sniff_quic_initial_sni(datagram: &[u8]) -> Option<String> {
    match QuicCryptoAssembler::default().feed(datagram) {
        QuicSniff::Domain(domain) => Some(domain),
        QuicSniff::NeedMore | QuicSniff::NoDomain => None,
    }
}

/// Exercises the QUIC Initial decoder without exposing it in normal builds.
/// Each element is one datagram of the same flow.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn sniff_quic_initial_sni_for_fuzzing<'a>(
    datagrams: impl IntoIterator<Item = &'a [u8]>,
) -> Option<String> {
    let mut assembler = QuicCryptoAssembler::default();
    for datagram in datagrams {
        match assembler.feed(datagram) {
            QuicSniff::Domain(domain) => return Some(domain),
            QuicSniff::NoDomain => return None,
            QuicSniff::NeedMore => {}
        }
    }
    None
}

enum QuicSniff {
    Domain(String),
    NeedMore,
    NoDomain,
}

enum ClientHelloState {
    Complete(Option<String>),
    Partial,
}

/// The CRYPTO stream of a client's Initial packets, reassembled across
/// coalesced packets and datagrams.
///
/// Only the gap-free prefix is parsed. Xray-core parses its zero-filled
/// buffer instead, where a missing piece reads as NUL bytes that can become
/// part of a server name.
#[derive(Default)]
struct QuicCryptoAssembler {
    stream: Vec<u8>,
    /// Received byte ranges, sorted and merged.
    received: Vec<(usize, usize)>,
}

impl QuicCryptoAssembler {
    fn feed(&mut self, datagram: &[u8]) -> QuicSniff {
        self.feed_packets(datagram).unwrap_or(QuicSniff::NoDomain)
    }

    fn feed_packets(&mut self, mut rest: &[u8]) -> Option<QuicSniff> {
        while !rest.is_empty() {
            let header = parse_quic_long_header(rest)?;
            if header.initial {
                let keys = quic_initial_keys(header.version, header.dcid)?;
                let unprotected = unprotect_quic_initial_header(rest, &header, &keys.hp)?;
                let plaintext = decrypt_quic_initial_packet(rest, &unprotected, &keys)?;
                self.add_frames(&plaintext)?;
                if let ClientHelloState::Complete(domain) = self.client_hello() {
                    return Some(domain.map_or(QuicSniff::NoDomain, QuicSniff::Domain));
                }
            }
            rest = &rest[header.payload_end..];
            // A datagram may be padded with zeros after its last packet.
            let padding = rest.iter().take_while(|&&byte| byte == 0).count();
            rest = &rest[padding..];
        }
        (!self.received.is_empty()).then_some(QuicSniff::NeedMore)
    }

    fn add_frames(&mut self, plaintext: &[u8]) -> Option<()> {
        let mut offset = 0usize;
        while offset < plaintext.len() {
            let frame_type = plaintext[offset];
            offset += 1;
            match frame_type {
                // PADDING and PING.
                0x00 | 0x01 => {}
                0x02 | 0x03 => {
                    offset = skip_quic_ack_frame(plaintext, offset, frame_type == 0x03)?;
                }
                0x06 => {
                    let (crypto_offset, used) = read_quic_varint(plaintext, offset)?;
                    offset = offset.checked_add(used)?;
                    let (crypto_len, used) = read_quic_varint(plaintext, offset)?;
                    offset = offset.checked_add(used)?;
                    let crypto_offset = usize::try_from(crypto_offset).ok()?;
                    let crypto_len = usize::try_from(crypto_len).ok()?;
                    let data_end = offset.checked_add(crypto_len)?;
                    let data = plaintext.get(offset..data_end)?;
                    self.insert(crypto_offset, data)?;
                    offset = data_end;
                }
                // CONNECTION_CLOSE, the only other frame an Initial may carry.
                0x1c => {
                    for _ in 0..2 {
                        let (_, used) = read_quic_varint(plaintext, offset)?;
                        offset = offset.checked_add(used)?;
                    }
                    let (reason_len, used) = read_quic_varint(plaintext, offset)?;
                    offset = offset.checked_add(used)?;
                    offset = offset.checked_add(usize::try_from(reason_len).ok()?)?;
                    plaintext.get(..offset)?;
                }
                _ => return None,
            }
        }
        Some(())
    }

    fn insert(&mut self, start: usize, data: &[u8]) -> Option<()> {
        let end = start.checked_add(data.len())?;
        if end > QUIC_MAX_CRYPTO_STREAM_SIZE {
            return None;
        }
        if data.is_empty() {
            return Some(());
        }
        if self.stream.len() < end {
            self.stream.resize(end, 0);
        }
        self.stream[start..end].copy_from_slice(data);

        let first = self
            .received
            .partition_point(|&(_, range_end)| range_end < start);
        let last = self
            .received
            .partition_point(|&(range_start, _)| range_start <= end);
        let merged = self.received[first..last]
            .iter()
            .fold((start, end), |(low, high), &(range_start, range_end)| {
                (low.min(range_start), high.max(range_end))
            });
        self.received.splice(first..last, [merged]);
        (self.received.len() <= QUIC_MAX_CRYPTO_RANGES).then_some(())
    }

    fn client_hello(&self) -> ClientHelloState {
        let prefix = match self.received.first() {
            Some(&(0, end)) => &self.stream[..end],
            _ => return ClientHelloState::Partial,
        };
        if prefix.len() < 4 {
            return ClientHelloState::Partial;
        }
        if prefix[0] != 1 {
            return ClientHelloState::Complete(None);
        }
        let Some(total) = read_u24(prefix, 1).map(|len| 4 + len as usize) else {
            return ClientHelloState::Partial;
        };
        if total > QUIC_MAX_CRYPTO_STREAM_SIZE {
            return ClientHelloState::Complete(None);
        }
        if prefix.len() < total {
            return ClientHelloState::Partial;
        }
        ClientHelloState::Complete(sniff_tls_client_hello_handshake_sni(&prefix[..total]))
    }
}

struct QuicLongHeader<'a> {
    version: u32,
    initial: bool,
    dcid: &'a [u8],
    packet_number_offset: usize,
    payload_end: usize,
    length: usize,
}

struct QuicInitialKeys {
    key: [u8; QUIC_INITIAL_KEY_LEN],
    iv: [u8; QUIC_INITIAL_IV_LEN],
    hp: [u8; QUIC_INITIAL_HP_LEN],
}

impl Drop for QuicInitialKeys {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        self.hp.zeroize();
    }
}

struct QuicUnprotectedHeader {
    header: Vec<u8>,
    packet_number: u64,
    ciphertext_offset: usize,
    payload_end: usize,
}

/// Parses one long-header packet. A client's first flight carries Initial
/// packets, possibly coalesced with 0-RTT ones, which are skipped by length.
fn parse_quic_long_header(packet: &[u8]) -> Option<QuicLongHeader<'_>> {
    let first = *packet.first()?;
    // Long header with the fixed bit set, as Xray-core requires.
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = read_u32(packet, 1)?;
    // RFC 9000 section 17.2 and RFC 9369 section 3.2 packet types.
    let (initial_type, retry_type) = match version {
        QUIC_V1 | QUIC_DRAFT_29 => (0x00, 0x30),
        QUIC_V2 => (0x10, 0x00),
        _ => return None,
    };
    let packet_type = first & 0x30;
    if packet_type == retry_type {
        return None;
    }
    let initial = packet_type == initial_type;

    let mut offset = 5usize;
    let dcid_len = usize::from(*packet.get(offset)?);
    offset += 1;
    let dcid_end = offset.checked_add(dcid_len)?;
    let dcid = packet.get(offset..dcid_end)?;
    offset = dcid_end;

    let scid_len = usize::from(*packet.get(offset)?);
    offset += 1;
    let scid_end = offset.checked_add(scid_len)?;
    packet.get(offset..scid_end)?;
    offset = scid_end;

    if initial {
        let (token_len, token_len_size) = read_quic_varint(packet, offset)?;
        offset = offset.checked_add(token_len_size)?;
        offset = offset.checked_add(usize::try_from(token_len).ok()?)?;
        packet.get(..offset)?;
    }

    let (length, length_size) = read_quic_varint(packet, offset)?;
    offset = offset.checked_add(length_size)?;
    let length = usize::try_from(length).ok()?;
    if initial && length <= QUIC_TAG_LEN {
        return None;
    }
    let payload_end = offset.checked_add(length)?;
    packet.get(..payload_end)?;

    Some(QuicLongHeader {
        version,
        initial,
        dcid,
        packet_number_offset: offset,
        payload_end,
        length,
    })
}

fn quic_initial_keys(version: u32, dcid: &[u8]) -> Option<QuicInitialKeys> {
    let salt = match version {
        QUIC_V1 => QUIC_V1_INITIAL_SALT,
        QUIC_V2 => QUIC_V2_INITIAL_SALT,
        QUIC_DRAFT_29 => QUIC_DRAFT_29_INITIAL_SALT,
        _ => return None,
    };
    let labels: [&[u8]; 3] = if version == QUIC_V2 {
        [b"quicv2 key", b"quicv2 iv", b"quicv2 hp"]
    } else {
        [b"quic key", b"quic iv", b"quic hp"]
    };
    let hk = Hkdf::<Sha256>::new(Some(&salt), dcid);
    let mut client_initial_secret = [0; QUIC_CLIENT_INITIAL_SECRET_LEN];
    hk.expand(
        &tls13_hkdf_label(QUIC_CLIENT_INITIAL_SECRET_LEN as u16, b"client in"),
        &mut client_initial_secret,
    )
    .ok()?;

    let keys = (|| {
        let hk = Hkdf::<Sha256>::from_prk(&client_initial_secret).ok()?;
        let mut key = [0; QUIC_INITIAL_KEY_LEN];
        hk.expand(
            &tls13_hkdf_label(QUIC_INITIAL_KEY_LEN as u16, labels[0]),
            &mut key,
        )
        .ok()?;
        let mut iv = [0; QUIC_INITIAL_IV_LEN];
        hk.expand(
            &tls13_hkdf_label(QUIC_INITIAL_IV_LEN as u16, labels[1]),
            &mut iv,
        )
        .ok()?;
        let mut hp = [0; QUIC_INITIAL_HP_LEN];
        hk.expand(
            &tls13_hkdf_label(QUIC_INITIAL_HP_LEN as u16, labels[2]),
            &mut hp,
        )
        .ok()?;

        Some(QuicInitialKeys { key, iv, hp })
    })();
    client_initial_secret.zeroize();
    keys
}

fn unprotect_quic_initial_header(
    packet: &[u8],
    header: &QuicLongHeader<'_>,
    hp_key: &[u8; QUIC_INITIAL_HP_LEN],
) -> Option<QuicUnprotectedHeader> {
    let sample_offset = header.packet_number_offset.checked_add(4)?;
    let sample = packet
        .get(..header.payload_end)?
        .get(sample_offset..sample_offset + QUIC_HP_SAMPLE_LEN)?;
    let mask = aes128_encrypt_block(hp_key, sample)?;
    let first = packet[0] ^ (mask[0] & 0x0f);
    let packet_number_len = usize::from((first & 0x03) + 1);
    if header.length <= packet_number_len + QUIC_TAG_LEN {
        return None;
    }
    let packet_number_end = header.packet_number_offset.checked_add(packet_number_len)?;
    if packet_number_end > header.payload_end {
        return None;
    }

    let mut unprotected = packet[..header.packet_number_offset].to_vec();
    unprotected[0] = first;
    let mut packet_number = 0u64;
    for index in 0..packet_number_len {
        let byte = packet[header.packet_number_offset + index] ^ mask[index + 1];
        unprotected.push(byte);
        packet_number = (packet_number << 8) | u64::from(byte);
    }

    Some(QuicUnprotectedHeader {
        header: unprotected,
        packet_number,
        ciphertext_offset: packet_number_end,
        payload_end: header.payload_end,
    })
}

fn decrypt_quic_initial_packet(
    packet: &[u8],
    header: &QuicUnprotectedHeader,
    keys: &QuicInitialKeys,
) -> Option<Vec<u8>> {
    let ciphertext = packet.get(header.ciphertext_offset..header.payload_end)?;
    let mut nonce = keys.iv;
    for (index, byte) in header.packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &header.header,
            },
        )
        .ok()
}

fn skip_quic_ack_frame(plaintext: &[u8], mut offset: usize, has_ecn: bool) -> Option<usize> {
    let (_, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;
    let (_, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;
    let (range_count, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;
    let (_, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;

    for _ in 0..range_count {
        let (_, used) = read_quic_varint(plaintext, offset)?;
        offset = offset.checked_add(used)?;
        let (_, used) = read_quic_varint(plaintext, offset)?;
        offset = offset.checked_add(used)?;
    }

    if has_ecn {
        for _ in 0..3 {
            let (_, used) = read_quic_varint(plaintext, offset)?;
            offset = offset.checked_add(used)?;
        }
    }

    Some(offset)
}

fn aes128_encrypt_block(key: &[u8; QUIC_INITIAL_HP_LEN], block: &[u8]) -> Option<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let mut block = aes::cipher::Block::<Aes128>::try_from(block).ok()?;
    cipher.encrypt_block(&mut block);
    Some(block.into())
}

fn parse_tls_sni_extension(extension: &[u8]) -> Option<String> {
    let list_len = read_u16(extension, 0)? as usize;
    if list_len + 2 > extension.len() {
        return None;
    }
    let mut offset = 2;
    let list_end = 2 + list_len;
    while offset + 3 <= list_end {
        let name_type = *extension.get(offset)?;
        let name_len = read_u16(extension, offset + 1)? as usize;
        offset += 3;
        let name_end = offset.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 {
            let host = std::str::from_utf8(&extension[offset..name_end]).ok()?;
            return normalize_host(host);
        }
        offset = name_end;
    }
    None
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    if host.starts_with('[') {
        return None;
    }
    let host_without_port = strip_port(host);
    if host_without_port.is_empty() {
        return None;
    }
    if host_without_port.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host_without_port.to_ascii_lowercase())
}

fn strip_port(host: &str) -> &str {
    let Some((domain, port)) = host.rsplit_once(':') else {
        return host;
    };
    if domain.contains(':') || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return host;
    }
    domain
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn read_u24(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(
        (u32::from(*bytes.get(offset)?) << 16)
            | (u32::from(*bytes.get(offset + 1)?) << 8)
            | u32::from(*bytes.get(offset + 2)?),
    )
}

fn read_quic_varint(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    let len = 1usize << usize::from(first >> 6);
    let raw = bytes.get(offset..offset + len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &raw[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

fn tls13_hkdf_label(length: u16, label: &[u8]) -> Vec<u8> {
    let full_label_len = b"tls13 ".len() + label.len();
    let mut output = Vec::with_capacity(2 + 1 + full_label_len + 1);
    output.extend_from_slice(&length.to_be_bytes());
    output.push(full_label_len as u8);
    output.extend_from_slice(b"tls13 ");
    output.extend_from_slice(label);
    output.push(0);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_config::SniffingDestination;
    use xray_routing::Network;

    fn sniffing_config(route_only: bool) -> InboundSniffingConfig {
        InboundSniffingConfig {
            enabled: true,
            dest_override: vec![SniffingDestination::Http, SniffingDestination::Tls],
            metadata_only: false,
            route_only,
            ..Default::default()
        }
    }

    fn original_ip_target() -> Target {
        Target::new(
            TargetAddr::Ip("127.0.0.1".parse().unwrap()),
            443,
            Network::Tcp,
        )
    }

    fn original_udp_target() -> Target {
        Target::new(
            TargetAddr::Ip("127.0.0.1".parse().unwrap()),
            443,
            Network::Udp,
        )
    }

    fn sniff_udp_initial_payload(
        config: &InboundSniffingConfig,
        original: &Target,
        payload: &[u8],
    ) -> Option<SniffedTarget> {
        match UdpSniffer::new(config, original).feed(payload) {
            UdpSniffProgress::Done(sniffed) => sniffed,
            UdpSniffProgress::NeedMore => None,
        }
    }

    /// Feeds the datagrams in order and records which ones left sniffing
    /// waiting for more.
    fn sniff_datagrams(datagrams: &[Vec<u8>]) -> (Vec<bool>, Option<String>) {
        let config = quic_sniffing_config(true);
        let original = original_udp_target();
        let mut sniffer = UdpSniffer::new(&config, &original);
        let mut waited = Vec::new();
        for datagram in datagrams {
            match sniffer.feed(datagram) {
                UdpSniffProgress::NeedMore => waited.push(true),
                UdpSniffProgress::Done(sniffed) => {
                    waited.push(false);
                    let domain = sniffed.map(|sniffed| match sniffed.route_target.addr {
                        TargetAddr::Domain(domain) => domain,
                        other => panic!("sniffing produced a non-domain target {other:?}"),
                    });
                    return (waited, domain);
                }
            }
        }
        (waited, None)
    }

    fn chrome_parrot_datagrams() -> Vec<Vec<u8>> {
        include_str!("../../../tests/fixtures/quic/xray-chrome-parrot-client-initials.hex")
            .lines()
            .map(|line| {
                (0..line.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn reassembles_xray_chrome_parrot_client_hello_across_datagrams() {
        // Captured from Xray-core v26.10.31's default ChromeParrot QUIC stack.
        let datagrams = chrome_parrot_datagrams();
        assert_eq!(datagrams.len(), 4);
        assert!(datagrams.iter().all(|datagram| datagram.len() == 1250));
        // Neither half alone carries the whole ClientHello.
        assert!(sniff_quic_initial_sni(&datagrams[0]).is_none());
        assert!(sniff_quic_initial_sni(&datagrams[1]).is_none());

        let (waited, domain) = sniff_datagrams(&datagrams);
        assert_eq!(waited, [true, false]);
        assert_eq!(domain.as_deref(), Some("chrome-parrot.example"));
        // Arrival order does not matter, nor do retransmitted pieces.
        let reordered = [datagrams[1].clone(), datagrams[0].clone()];
        assert_eq!(
            sniff_datagrams(&reordered).1.as_deref(),
            Some("chrome-parrot.example")
        );
        let retransmitted = [
            datagrams[0].clone(),
            datagrams[2].clone(),
            datagrams[3].clone(),
        ];
        assert_eq!(
            sniff_datagrams(&retransmitted).1.as_deref(),
            Some("chrome-parrot.example")
        );
    }

    #[test]
    fn reassembles_scattered_crypto_frames_from_coalesced_and_later_packets() {
        let hello = tls_client_hello_handshake_with_padding_and_sni(1800, "split.example");
        let crypto = |start: usize, end: usize| crypto_frame(start, &hello[start..end]);
        let first = [
            quic_initial_packet(0, &[crypto(1200, hello.len()), vec![0x01]].concat()),
            quic_initial_packet(1, &[vec![0; 8], crypto(0, 400)].concat()),
        ]
        .concat();
        let second = quic_initial_packet(2, &crypto(400, 1200));

        let (waited, domain) = sniff_datagrams(&[first.clone(), second.clone()]);
        assert_eq!(waited, [true, false]);
        assert_eq!(domain.as_deref(), Some("split.example"));

        // A coalesced 0-RTT packet is skipped by its length.
        let zero_rtt = quic_long_header_packet(0xd0, &[0x55; 40]);
        let with_zero_rtt = [first, zero_rtt, second].concat();
        assert_eq!(
            sniff_datagrams(&[with_zero_rtt]).1.as_deref(),
            Some("split.example")
        );
    }

    #[test]
    fn never_parses_bytes_that_have_not_arrived() {
        // Xray-core zero-fills a missing piece, which can put NUL bytes in the
        // middle of a parsed server name.
        let host = "gap-in-the-name.example";
        let hello = tls_client_hello_handshake_with_padding_and_sni(0, host);
        let name = hello.len() - host.len();
        let gap = name + 4..name + 9;
        let around = quic_initial_packet(
            0,
            &[
                crypto_frame(0, &hello[..gap.start]),
                crypto_frame(gap.end, &hello[gap.end..]),
            ]
            .concat(),
        );
        let filler = quic_initial_packet(1, &crypto_frame(gap.start, &hello[gap.clone()]));

        let (waited, domain) = sniff_datagrams(&[around, filler]);
        assert_eq!(waited, [true, false]);
        assert_eq!(domain.as_deref(), Some(host));
    }

    #[test]
    fn stops_waiting_when_more_data_cannot_help() {
        let hello = tls_client_hello_handshake_with_padding_and_sni(400, "done.example");
        // Not QUIC, a complete ClientHello without SNI, and a ClientHello that
        // could only complete beyond the reassembly limit.
        let without_sni = tls_client_hello_handshake_with_padding_and_sni(64, "");
        let oversized = crypto_frame(0, &[1, 0x00, 0x80, 0x00]);
        let beyond_limit = crypto_frame(QUIC_MAX_CRYPTO_STREAM_SIZE, &[0]);
        for datagram in [
            b"\x13\x37 not a QUIC packet".to_vec(),
            quic_initial_packet(0, &crypto_frame(0, &without_sni)),
            quic_initial_packet(0, &oversized),
            quic_initial_packet(0, &beyond_limit),
        ] {
            assert_eq!(sniff_datagrams(&[datagram]), (vec![false], None));
        }

        // Too many disjoint pieces of one ClientHello.
        let scattered: Vec<u8> = (0..=QUIC_MAX_CRYPTO_RANGES)
            .flat_map(|piece| crypto_frame(2 * piece + 1, &hello[2 * piece + 1..2 * piece + 2]))
            .collect();
        assert_eq!(
            sniff_datagrams(&[quic_initial_packet(0, &scattered)]),
            (vec![false], None)
        );
    }

    fn quic_sniffing_config(route_only: bool) -> InboundSniffingConfig {
        InboundSniffingConfig {
            enabled: true,
            dest_override: vec![SniffingDestination::Quic],
            metadata_only: false,
            route_only,
            ..Default::default()
        }
    }

    #[test]
    fn sniffs_http_host_header() {
        let payload = b"GET / HTTP/1.1\r\nHost: Routed.Example:443\r\nUser-Agent: test\r\n\r\n";
        let sniffed =
            sniff_tcp_initial_payload(&sniffing_config(true), &original_ip_target(), payload)
                .expect("HTTP host should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("routed.example".to_owned())
        );
        assert_eq!(sniffed.protocol, SniffingDestination::Http);
    }

    #[test]
    fn sniffs_tls_client_hello_sni() {
        let payload = tls_client_hello_with_sni("tls.example");
        let sniffed =
            sniff_tcp_initial_payload(&sniffing_config(true), &original_ip_target(), &payload)
                .expect("TLS SNI should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("tls.example".to_owned())
        );
        assert_eq!(sniffed.protocol, SniffingDestination::Tls);
    }

    #[test]
    fn route_only_keeps_original_target_for_dialing() {
        let original = original_ip_target();
        let payload = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
        let sniffed = sniff_tcp_initial_payload(&sniffing_config(true), &original, payload)
            .expect("HTTP host should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("routed.example".to_owned())
        );
        assert_eq!(sniffed.dial_target, original);
    }

    #[test]
    fn rejects_empty_http_host_after_stripping_port() {
        let payload = b"GET / HTTP/1.1\r\nHost: :443\r\n\r\n";

        assert!(
            sniff_tcp_initial_payload(&sniffing_config(true), &original_ip_target(), payload)
                .is_none()
        );
    }

    /// `config` with `domainsExcluded` of `domains` and `ipsExcluded` of
    /// `ips`.
    fn excluding(
        config: InboundSniffingConfig,
        domains: &[xray_config::DomainMatcher],
        ips: &[&str],
    ) -> InboundSniffingConfig {
        let mut ips_excluded = xray_config::IpMatcherSet::builder();
        for ip in ips {
            ips_excluded.insert_ip(ip.parse().unwrap(), false);
        }
        InboundSniffingConfig {
            domains_excluded: xray_config::compile_domain_matchers(domains).unwrap(),
            ips_excluded: ips_excluded.build(),
            ..config
        }
    }

    #[test]
    fn excluded_domains_keep_the_original_destination() {
        let config = excluding(
            sniffing_config(true),
            &[xray_config::DomainMatcher::Keyword(
                "push.apple.com".to_owned(),
            )],
            &[],
        );
        let excluded = b"GET / HTTP/1.1\r\nHost: Courier.Push.Apple.Com\r\n\r\n";
        assert!(sniff_tcp_initial_payload(&config, &original_ip_target(), excluded).is_none());
        let tls = tls_client_hello_with_sni("courier.push.apple.com");
        assert!(sniff_tcp_initial_payload(&config, &original_ip_target(), &tls).is_none());

        let other = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
        assert!(sniff_tcp_initial_payload(&config, &original_ip_target(), other).is_some());
    }

    #[test]
    fn excluded_destination_ips_keep_whatever_is_sniffed_away() {
        let config = excluding(sniffing_config(false), &[], &["127.0.0.1"]);
        let payload = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
        assert!(sniff_tcp_initial_payload(&config, &original_ip_target(), payload).is_none());

        // Only an IP destination is checked, as in Xray-core.
        let by_name = Target::new(
            TargetAddr::Domain("localhost".to_owned()),
            443,
            Network::Tcp,
        );
        assert!(sniff_tcp_initial_payload(&config, &by_name, payload).is_some());
        let elsewhere = Target::new(
            TargetAddr::Ip("192.0.2.1".parse().unwrap()),
            443,
            Network::Tcp,
        );
        assert!(sniff_tcp_initial_payload(&config, &elsewhere, payload).is_some());
    }

    #[test]
    fn quic_sniffing_honors_domain_exclusions() {
        let config = excluding(
            quic_sniffing_config(true),
            &[xray_config::DomainMatcher::Full("quic.example".to_owned())],
            &[],
        );
        let payload = quic_initial_packet_with_sni("quic.example");
        assert!(sniff_udp_initial_payload(&config, &original_udp_target(), &payload).is_none());
        let other = quic_initial_packet_with_sni("other.example");
        assert!(sniff_udp_initial_payload(&config, &original_udp_target(), &other).is_some());
    }

    #[test]
    fn non_route_only_replaces_dial_target() {
        let original = original_ip_target();
        let payload = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
        let sniffed = sniff_tcp_initial_payload(&sniffing_config(false), &original, payload)
            .expect("HTTP host should be sniffed");

        assert_eq!(sniffed.dial_target, sniffed.route_target);
    }

    #[test]
    fn sniffs_quic_initial_sni() {
        let payload = quic_initial_packet_with_sni("quic.example");
        let sniffed = sniff_udp_initial_payload(
            &quic_sniffing_config(true),
            &original_udp_target(),
            &payload,
        )
        .expect("QUIC SNI should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("quic.example".to_owned())
        );
        assert_eq!(sniffed.dial_target, original_udp_target());
        assert_eq!(sniffed.protocol, SniffingDestination::Quic);
    }

    #[test]
    fn rejects_unknown_quic_version() {
        let mut payload = quic_initial_packet_with_sni("quic.example");
        payload[1..5].copy_from_slice(&2u32.to_be_bytes());

        assert!(sniff_udp_initial_payload(
            &quic_sniffing_config(true),
            &original_udp_target(),
            &payload
        )
        .is_none());
    }

    #[test]
    fn sniffs_rfc9369_v2_client_initial_and_rejects_corruption() {
        // RFC 9369 Appendix A.2: independently published authenticated packet.
        let hex = include_str!("../../../tests/fixtures/quic/rfc9369-client-initial.hex");
        let mut packet: Vec<u8> = hex
            .split_whitespace()
            .flat_map(|word| {
                (0..word.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&word[i..i + 2], 16).unwrap())
            })
            .collect();
        assert_eq!(
            sniff_quic_initial_sni(&packet).as_deref(),
            Some("example.com")
        );
        // Coalesced/padded datagram bytes do not enter the Initial ciphertext.
        packet.extend_from_slice(&[0; 64]);
        assert_eq!(
            sniff_quic_initial_sni(&packet).as_deref(),
            Some("example.com")
        );
        packet[40] ^= 1;
        assert!(sniff_quic_initial_sni(&packet).is_none());
        packet[40] ^= 1;
        packet[0] ^= 0x10; // v2 Retry cannot be treated as a v1 Initial
        assert!(sniff_quic_initial_sni(&packet).is_none());
        packet[0] ^= 0x10;
        assert!(sniff_quic_initial_sni(&packet[..packet.len() - 65]).is_none());
    }

    #[test]
    fn sniffs_rfc9001_v1_client_initial_and_rejects_corruption() {
        // RFC 9001 Appendix A.2: the v1 counterpart, so the v1 salt, labels and
        // header protection are checked against a published packet rather
        // than one this module built itself.
        let hex = include_str!("../../../tests/fixtures/quic/rfc9001-client-initial.hex");
        let mut packet: Vec<u8> = hex
            .split_whitespace()
            .flat_map(|word| {
                (0..word.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&word[i..i + 2], 16).unwrap())
            })
            .collect();
        assert_eq!(packet.len(), 1200);
        assert_eq!(
            sniff_quic_initial_sni(&packet).as_deref(),
            Some("example.com")
        );
        packet.extend_from_slice(&[0; 64]);
        assert_eq!(
            sniff_quic_initial_sni(&packet).as_deref(),
            Some("example.com")
        );
        packet[40] ^= 1;
        assert!(sniff_quic_initial_sni(&packet).is_none());
        packet[40] ^= 1;
        packet[0] ^= 0x10; // v1 0-RTT is not an Initial
        assert!(sniff_quic_initial_sni(&packet).is_none());
        packet[0] ^= 0x10;
        assert!(sniff_quic_initial_sni(&packet[..packet.len() - 65]).is_none());
    }

    #[test]
    fn rejects_malformed_quic_initial_sni() {
        let payload = [0xc0, 0, 0, 0, 1, 8, 1, 2, 3];

        assert!(sniff_udp_initial_payload(
            &quic_sniffing_config(true),
            &original_udp_target(),
            &payload
        )
        .is_none());
    }

    fn tls_client_hello_handshake_with_sni(host: &str) -> Vec<u8> {
        tls_client_hello_handshake_with_padding_and_sni(0, host)
    }

    /// A ClientHello whose padding extension, when `padding` is nonzero,
    /// precedes the SNI, so the name lands late as with Chrome's shuffled
    /// extensions. An empty `host` omits the SNI extension.
    fn tls_client_hello_handshake_with_padding_and_sni(padding: usize, host: &str) -> Vec<u8> {
        let mut extensions = Vec::new();
        if padding > 0 {
            extensions.extend_from_slice(&21u16.to_be_bytes());
            extensions.extend_from_slice(&(padding as u16).to_be_bytes());
            extensions.resize(extensions.len() + padding, 0);
        }
        if !host.is_empty() {
            let mut sni_entry = Vec::new();
            sni_entry.push(0);
            sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni_entry.extend_from_slice(host.as_bytes());

            let mut sni_extension = Vec::new();
            sni_extension.extend_from_slice(&((sni_entry.len()) as u16).to_be_bytes());
            sni_extension.extend_from_slice(&sni_entry);

            extensions.extend_from_slice(&0u16.to_be_bytes());
            extensions.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_extension);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn tls_client_hello_with_sni(host: &str) -> Vec<u8> {
        let handshake = tls_client_hello_handshake_with_sni(host);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        encode_quic_varint(offset as u64, &mut frame);
        encode_quic_varint(data.len() as u64, &mut frame);
        frame.extend_from_slice(data);
        frame
    }

    fn quic_initial_packet_with_sni(host: &str) -> Vec<u8> {
        quic_initial_packet(
            0,
            &crypto_frame(0, &tls_client_hello_handshake_with_sni(host)),
        )
    }

    const TEST_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    const TEST_SCID: [u8; 8] = [0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

    /// An unprotected long-header packet that sniffing must skip by length.
    fn quic_long_header_packet(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![first];
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.push(TEST_DCID.len() as u8);
        packet.extend_from_slice(&TEST_DCID);
        packet.push(TEST_SCID.len() as u8);
        packet.extend_from_slice(&TEST_SCID);
        encode_quic_varint(payload.len() as u64, &mut packet);
        packet.extend_from_slice(payload);
        packet
    }

    /// A protected QUIC v1 client Initial carrying `plaintext` frames.
    fn quic_initial_packet(packet_number: u8, plaintext: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        use aes::Aes128;
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes128Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha256;

        const INITIAL_SALT: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];

        let packet_number_len = 1usize;

        let initial_secret = {
            let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &TEST_DCID);
            let mut secret = [0u8; 32];
            hk.expand(&hkdf_label(32, b"client in"), &mut secret)
                .expect("initial secret label is valid");
            secret
        };
        let hk = Hkdf::<Sha256>::from_prk(&initial_secret).expect("initial secret is valid");
        let mut key = [0u8; 16];
        hk.expand(&hkdf_label(16, b"quic key"), &mut key)
            .expect("key label is valid");
        let mut iv = [0u8; 12];
        hk.expand(&hkdf_label(12, b"quic iv"), &mut iv)
            .expect("iv label is valid");
        let mut hp = [0u8; 16];
        hk.expand(&hkdf_label(16, b"quic hp"), &mut hp)
            .expect("hp label is valid");

        let mut header = Vec::new();
        header.push(0xc0);
        header.extend_from_slice(&1u32.to_be_bytes());
        header.push(TEST_DCID.len() as u8);
        header.extend_from_slice(&TEST_DCID);
        header.push(TEST_SCID.len() as u8);
        header.extend_from_slice(&TEST_SCID);
        encode_quic_varint(0, &mut header);
        encode_quic_varint(
            packet_number_len as u64 + plaintext.len() as u64 + 16,
            &mut header,
        );
        let packet_number_offset = header.len();
        header.push(packet_number);

        let mut nonce = iv;
        nonce[11] ^= packet_number;
        let cipher = Aes128Gcm::new_from_slice(&key).expect("key length is valid");
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .expect("fixture encryption should succeed");

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let sample_offset = packet_number_offset + 4;
        let mask = {
            let cipher = Aes128::new_from_slice(&hp).expect("hp key length is valid");
            let mut block =
                aes::cipher::Block::<Aes128>::try_from(&packet[sample_offset..sample_offset + 16])
                    .expect("sample is one AES block");
            cipher.encrypt_block(&mut block);
            block
        };
        packet[0] ^= mask[0] & 0x0f;
        for index in 0..packet_number_len {
            packet[packet_number_offset + index] ^= mask[index + 1];
        }
        packet
    }

    fn encode_quic_varint(value: u64, output: &mut Vec<u8>) {
        if value < 64 {
            output.push(value as u8);
        } else if value < 16_384 {
            let encoded = (value as u16) | 0x4000;
            output.extend_from_slice(&encoded.to_be_bytes());
        } else if value < 1 << 30 {
            let encoded = (value as u32) | 0x8000_0000;
            output.extend_from_slice(&encoded.to_be_bytes());
        } else {
            panic!("test varint value is too large: {value}");
        }
    }

    fn hkdf_label(length: u16, label: &[u8]) -> Vec<u8> {
        let full_label_len = b"tls13 ".len() + label.len();
        let mut output = Vec::with_capacity(2 + 1 + full_label_len + 1);
        output.extend_from_slice(&length.to_be_bytes());
        output.push(full_label_len as u8);
        output.extend_from_slice(b"tls13 ");
        output.extend_from_slice(label);
        output.push(0);
        output
    }
}
