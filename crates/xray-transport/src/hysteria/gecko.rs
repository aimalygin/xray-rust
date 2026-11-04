//! Gecko, the shape layer Hysteria 2.9.2 added on top of Salamander and Xray
//! adopted as Salamander's `packetSize`. QUIC long-header (handshake)
//! datagrams travel as two to eight randomly padded fragments; short-header
//! datagrams pass through unchanged. Each fragment is its own Salamander
//! datagram, with its own salt.
//!
//! Frame layout, after Salamander decryption:
//!
//! ```text
//! byte 0     0x80 (fragment marker; the low seven bits are reserved)
//! byte 1     message ID
//! byte 2     chunk index (high nibble) | chunk count (low nibble, 2..=8)
//! bytes 3-4  padding length, big-endian
//! padding, then the chunk
//! ```
use std::time::{Duration, Instant};

use rand::Rng;

use super::carrier::SALT_LEN;

const FRAGMENT_FLAG: u8 = 0x80;
const HEADER_LEN: usize = 5;
const MIN_CHUNKS: usize = 2;
const MAX_CHUNKS: usize = 8;
/// An incomplete message is dropped this long after its first chunk.
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
/// Incomplete messages held per peer, as Gecko's per-source cap.
const MAX_INCOMPLETE: usize = 8;
/// Gecko's read buffer, which bounds `packetSize`.
const MAX_PACKET_SIZE: u16 = 2048;
/// Padding never grows a datagram past the carrier's own datagram budget:
/// 1,452 bytes, which carries IPv6 on 1,500-byte links. Gecko pads up to
/// 2,048 bytes. Xray's masked socket never gets the don't-fragment flag, so
/// larger datagrams leave IP-fragmented; Hysteria sets the flag, as Quinn does
/// here, and a fragment past the path MTU is lost, stalling the handshake.
const PADDED_LIMIT: usize = 1452;
/// A message larger than any UDP datagram is malformed.
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

/// Gecko's datagram size range: padding makes each fragment, salt included,
/// a random size in `min..=max` when its chunk leaves room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeckoPacketSize {
    pub min: u16,
    pub max: u16,
}

impl GeckoPacketSize {
    /// Gecko's bounds: `1 <= min <= max <= 2048`.
    pub fn new(min: u16, max: u16) -> Option<Self> {
        Some(Self { min, max }).filter(|size| size.is_valid())
    }

    pub(crate) fn is_valid(self) -> bool {
        self.min > 0 && self.min <= self.max && self.max <= MAX_PACKET_SIZE
    }
}

/// Gecko fragments a datagram whose first byte has the QUIC long-header bit.
pub(crate) fn is_fragmented(datagram: &[u8]) -> bool {
    datagram
        .first()
        .is_some_and(|byte| byte & FRAGMENT_FLAG != 0)
}

/// The frames for one long-header datagram: a random count of near-equal
/// chunks, the last taking the remainder, each with random padding.
pub(crate) fn fragment(
    datagram: &[u8],
    message: u8,
    size: GeckoPacketSize,
    rng: &mut impl Rng,
) -> Vec<Vec<u8>> {
    let chunks = rng.gen_range(MIN_CHUNKS..=MAX_CHUNKS);
    let chunk_len = datagram.len() / chunks;
    (0..chunks)
        .map(|index| {
            let start = index * chunk_len;
            let end = if index + 1 < chunks {
                start + chunk_len
            } else {
                datagram.len()
            };
            let chunk = &datagram[start..end];
            let padding = padding_len(size, chunk.len(), rng);
            let mut frame = Vec::with_capacity(HEADER_LEN + padding + chunk.len());
            frame.extend_from_slice(&[FRAGMENT_FLAG, message, (index << 4 | chunks) as u8]);
            frame.extend_from_slice(&(padding as u16).to_be_bytes());
            frame.resize(HEADER_LEN + padding, 0);
            rng.fill(&mut frame[HEADER_LEN..]);
            frame.extend_from_slice(chunk);
            frame
        })
        .collect()
}

/// Padding that brings the wire datagram (salt, header, padding and chunk)
/// to a random size between the larger of `min` and its unpadded size, and
/// `max`; none when the chunk alone exceeds `max`.
fn padding_len(size: GeckoPacketSize, chunk_len: usize, rng: &mut impl Rng) -> usize {
    let max = usize::from(size.max).min(PADDED_LIMIT);
    let min = usize::from(size.min).min(max);
    let unpadded = SALT_LEN + HEADER_LEN + chunk_len;
    let low = min.max(unpadded);
    if low > max {
        return 0;
    }
    low - unpadded + rng.gen_range(0..=max - low)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame<'a> {
    message: u8,
    index: u8,
    chunks: u8,
    payload: &'a [u8],
}

/// Parses one decrypted frame; malformed frames are dropped by the caller.
pub(crate) fn parse_frame(input: &[u8]) -> Option<Frame<'_>> {
    if input.len() < HEADER_LEN || input[0] & FRAGMENT_FLAG == 0 {
        return None;
    }
    let (index, chunks) = (input[2] >> 4, input[2] & 0x0f);
    if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&usize::from(chunks)) || index >= chunks {
        return None;
    }
    let padding = usize::from(u16::from_be_bytes([input[3], input[4]]));
    Some(Frame {
        message: input[1],
        index,
        chunks,
        payload: input.get(HEADER_LEN + padding..)?,
    })
}

struct Message {
    id: u8,
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    len: usize,
    deadline: Instant,
}

/// Reassembly for the one peer a carrier socket accepts datagrams from.
#[derive(Default)]
pub(crate) struct Reassembly {
    messages: Vec<Message>,
}

impl Reassembly {
    /// Stores a chunk, returning its message once every chunk has arrived.
    /// Like Gecko, it drops a chunk for a new message while eight are
    /// incomplete, a chunk whose count disagrees with its message, and a
    /// duplicate.
    pub(crate) fn accept(&mut self, now: Instant, frame: Frame<'_>) -> Option<Vec<u8>> {
        self.messages.retain(|message| message.deadline >= now);
        let position = match self.messages.iter().position(|m| m.id == frame.message) {
            Some(position) if self.messages[position].chunks.len() == usize::from(frame.chunks) => {
                position
            }
            Some(_) => return None,
            None if self.messages.len() >= MAX_INCOMPLETE => return None,
            None => {
                self.messages.push(Message {
                    id: frame.message,
                    chunks: vec![None; usize::from(frame.chunks)],
                    received: 0,
                    len: 0,
                    deadline: now + REASSEMBLY_TTL,
                });
                self.messages.len() - 1
            }
        };
        let message = &mut self.messages[position];
        let slot = &mut message.chunks[usize::from(frame.index)];
        if slot.is_some() {
            return None;
        }
        message.len += frame.payload.len();
        if message.len > MAX_MESSAGE_LEN {
            self.messages.swap_remove(position);
            return None;
        }
        *slot = Some(frame.payload.to_vec());
        message.received += 1;
        if message.received < message.chunks.len() {
            return None;
        }
        let message = self.messages.swap_remove(position);
        Some(message.chunks.into_iter().flatten().flatten().collect())
    }

    #[cfg(test)]
    fn incomplete(&self) -> usize {
        self.messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    const SIZE: GeckoPacketSize = GeckoPacketSize {
        min: 100,
        max: 1200,
    };

    fn frames(datagram: &[u8], message: u8, seed: u64) -> Vec<Vec<u8>> {
        fragment(datagram, message, SIZE, &mut StdRng::seed_from_u64(seed))
    }

    #[test]
    fn frames_follow_geckos_layout() {
        // Built by hand from Gecko's encodeFrame: marker, message ID,
        // index:count, big-endian padding length, padding, chunk.
        let datagram: Vec<u8> = (0..=255).collect();
        for seed in 0..64 {
            let frames = frames(&datagram, 0x5a, seed);
            assert!((2..=8).contains(&frames.len()));
            let chunk_len = datagram.len() / frames.len();
            let mut joined = Vec::new();
            for (index, frame) in frames.iter().enumerate() {
                assert_eq!(frame[0], 0x80);
                assert_eq!(frame[1], 0x5a);
                assert_eq!(usize::from(frame[2] >> 4), index);
                assert_eq!(usize::from(frame[2] & 0x0f), frames.len());
                let padding = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
                let chunk = &frame[HEADER_LEN + padding..];
                if index + 1 < frames.len() {
                    assert_eq!(chunk.len(), chunk_len);
                }
                // Salt, header, padding and chunk land in packetSize.
                let wire = SALT_LEN + frame.len();
                assert!((100..=1200).contains(&wire), "{wire}");
                joined.extend_from_slice(chunk);
            }
            assert_eq!(joined, datagram);
        }
    }

    #[test]
    fn padding_spans_the_range_and_stops_at_the_carrier_budget() {
        let mut rng = StdRng::seed_from_u64(1);
        let sizes = |size: GeckoPacketSize, chunk: usize, rng: &mut StdRng| {
            let wire =
                |rng: &mut StdRng| SALT_LEN + HEADER_LEN + chunk + padding_len(size, chunk, rng);
            let all: Vec<usize> = (0..20_000).map(|_| wire(rng)).collect();
            (*all.iter().min().unwrap(), *all.iter().max().unwrap())
        };
        // Uniform over the whole range when the chunk is small.
        assert_eq!(sizes(SIZE, 37, &mut rng), (100, 1200));
        // The unpadded size raises the floor.
        assert_eq!(sizes(SIZE, 600, &mut rng), (613, 1200));
        // A chunk past the ceiling travels unpadded.
        assert_eq!(sizes(SIZE, 1300, &mut rng), (1313, 1313));
        // A single size is exact.
        let exact = GeckoPacketSize { min: 700, max: 700 };
        assert_eq!(sizes(exact, 10, &mut rng), (700, 700));
        // Padding stops at 1,452 bytes; a floor above it collapses there.
        let wide = GeckoPacketSize {
            min: 1000,
            max: 2048,
        };
        assert_eq!(sizes(wide, 10, &mut rng), (1000, 1452));
        let high = GeckoPacketSize {
            min: 1500,
            max: 2048,
        };
        assert_eq!(sizes(high, 10, &mut rng), (1452, 1452));
        assert_eq!(sizes(high, 1500, &mut rng), (1513, 1513));
    }

    #[test]
    fn short_datagrams_still_fragment() {
        // Gecko divides by the chunk count, so leading chunks may be empty.
        let frames = fragment(&[0xc0], 1, SIZE, &mut StdRng::seed_from_u64(3));
        let payloads: Vec<&[u8]> = frames
            .iter()
            .map(|f| parse_frame(f).unwrap().payload)
            .collect();
        assert_eq!(payloads.concat(), [0xc0]);
        assert!(payloads[..payloads.len() - 1].iter().all(|p| p.is_empty()));
    }

    #[test]
    fn only_long_headers_fragment() {
        assert!(is_fragmented(&[0xc3, 0, 0, 0, 1]));
        assert!(is_fragmented(&[0x80]));
        assert!(!is_fragmented(&[0x40, 1, 2]));
        assert!(!is_fragmented(&[]));
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let valid = [0x80, 7, 0x12, 0, 1, 0xee, b'x'];
        assert_eq!(
            parse_frame(&valid),
            Some(Frame {
                message: 7,
                index: 1,
                chunks: 2,
                payload: b"x"
            })
        );
        // Padding may end exactly at the end of the datagram.
        assert_eq!(parse_frame(&[0x80, 7, 0x02, 0, 0]).unwrap().payload, b"");
        for invalid in [
            &[0x80, 7, 0x12, 0][..],          // Truncated header.
            &[0x40, 7, 0x12, 0, 0][..],       // Short-header bit pattern.
            &[0x80, 7, 0x01, 0, 0][..],       // One chunk.
            &[0x80, 7, 0x09, 0, 0][..],       // Nine chunks.
            &[0x80, 7, 0x22, 0, 0][..],       // Index past the count.
            &[0x80, 7, 0x02, 0, 3, 1, 2][..], // Padding past the end.
        ] {
            assert_eq!(parse_frame(invalid), None, "{invalid:02x?}");
        }
    }

    #[test]
    fn reassembly_accepts_any_order_and_drops_like_gecko() {
        let now = Instant::now();
        let datagram: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let mut frames = frames(&datagram, 9, 11);
        frames.reverse();
        let mut reassembly = Reassembly::default();
        let (last, rest) = frames.split_last().unwrap();
        for frame in rest {
            assert_eq!(reassembly.accept(now, parse_frame(frame).unwrap()), None);
            // A duplicate is ignored.
            assert_eq!(reassembly.accept(now, parse_frame(frame).unwrap()), None);
        }
        assert_eq!(
            reassembly.accept(now, parse_frame(last).unwrap()),
            Some(datagram.clone())
        );
        assert_eq!(reassembly.incomplete(), 0);

        // A chunk whose count disagrees with its message is dropped.
        assert_eq!(
            reassembly.accept(now, parse_frame(&[0x80, 1, 0x02, 0, 0, b'a']).unwrap()),
            None
        );
        assert_eq!(
            reassembly.accept(now, parse_frame(&[0x80, 1, 0x13, 0, 0, b'b']).unwrap()),
            None
        );
        assert_eq!(
            reassembly.accept(now, parse_frame(&[0x80, 1, 0x12, 0, 0, b'c']).unwrap()),
            Some(b"ac".to_vec())
        );

        // Eight incomplete messages block a ninth until they expire.
        for id in 0..8 {
            reassembly.accept(now, parse_frame(&[0x80, id, 0x02, 0, 0]).unwrap());
        }
        let ninth = [0x80, 8, 0x02, 0, 0, b'n'];
        assert_eq!(reassembly.accept(now, parse_frame(&ninth).unwrap()), None);
        assert_eq!(reassembly.incomplete(), 8);
        // Chunks of held messages still complete them.
        assert_eq!(
            reassembly.accept(now, parse_frame(&[0x80, 3, 0x12, 0, 0, b'z']).unwrap()),
            Some(b"z".to_vec())
        );
        let later = now + REASSEMBLY_TTL + Duration::from_millis(1);
        assert_eq!(reassembly.accept(later, parse_frame(&ninth).unwrap()), None);
        assert_eq!(reassembly.incomplete(), 1);
        assert_eq!(
            reassembly.accept(later, parse_frame(&[0x80, 8, 0x12, 0, 0, b'!']).unwrap()),
            Some(b"n!".to_vec())
        );
    }

    #[test]
    fn oversized_messages_are_dropped() {
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        let mut big = vec![0x80, 4, 0x03, 0, 0];
        big.resize(HEADER_LEN + 40_000, 0);
        assert_eq!(reassembly.accept(now, parse_frame(&big).unwrap()), None);
        big[2] = 0x13;
        assert_eq!(reassembly.accept(now, parse_frame(&big).unwrap()), None);
        assert_eq!(reassembly.incomplete(), 0);
    }

    #[test]
    fn packet_size_bounds() {
        assert_eq!(GeckoPacketSize::new(100, 1200), Some(SIZE));
        assert!(GeckoPacketSize::new(1, 2048).is_some());
        for (min, max) in [(0, 100), (200, 100), (1, 2049)] {
            assert_eq!(GeckoPacketSize::new(min, max), None);
            assert!(!GeckoPacketSize { min, max }.is_valid());
        }
    }
}
