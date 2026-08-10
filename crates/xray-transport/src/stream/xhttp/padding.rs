//! XHTTP request-padding generation.
//!
//! `tokenish` targets the encoded HPACK/QPACK byte length, not the cleartext
//! character count. Xray uses the RFC 7541 static Huffman table and falls back
//! to repeat-X if its CSPRNG fails; both details affect the wire fingerprint.

use std::collections::TryReserveError;

use rand::RngCore;
use thiserror::Error;

use super::config::{NormalizedRange, XhttpPaddingMethod};

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE62_REJECTION_LIMIT: u8 = 248;
const TOKENISH_TOLERANCE_BYTES: usize = 2;
const TOKENISH_MAX_ADJUSTMENTS: usize = 150;

#[derive(Debug, Error)]
pub enum PaddingError {
    #[error("XHTTP random source failed: {0}")]
    Random(#[source] rand::Error),
    #[error("XHTTP padding allocation failed: {0}")]
    Allocation(#[from] TryReserveError),
    #[error("XHTTP padding length does not fit this target")]
    TooLarge,
    #[error("XHTTP normalized range has descending bounds")]
    DescendingRange,
}

/// Draws from Xray's half-open `[from, to)` range; equal bounds are exact.
pub fn draw_range<R: RngCore + ?Sized>(
    range: NormalizedRange,
    rng: &mut R,
) -> Result<u32, PaddingError> {
    if range.from > range.to {
        return Err(PaddingError::DescendingRange);
    }
    if range.from == range.to {
        return Ok(range.from);
    }

    let span = u64::from(range.to - range.from);
    // Reject the short prefix whose inclusion would bias `% span`. This is
    // equivalent to crypto/rand.Int while consuming fixed-size RNG blocks.
    let threshold = span.wrapping_neg() % span;
    loop {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(PaddingError::Random)?;
        let sample = u64::from_le_bytes(bytes);
        if sample >= threshold {
            return Ok(range.from + (sample % span) as u32);
        }
    }
}

pub fn generate_padding<R: RngCore + ?Sized>(
    method: XhttpPaddingMethod,
    length: u32,
    rng: &mut R,
) -> Result<String, PaddingError> {
    if length == 0 {
        return Ok(String::new());
    }

    match method {
        XhttpPaddingMethod::RepeatX => repeat_x(length),
        XhttpPaddingMethod::Tokenish => match generate_tokenish(length, rng)? {
            Some(padding) => Ok(padding),
            None => repeat_x(length),
        },
    }
}

fn repeat_x(length: u32) -> Result<String, PaddingError> {
    let length = length as usize;
    let mut padding = String::new();
    padding.try_reserve_exact(length)?;
    padding.extend(std::iter::repeat_n('X', length));
    Ok(padding)
}

/// Returns `None` only when the random source fails, which signals the
/// repeat-X fallback used by Xray. Allocation failures remain real errors.
fn generate_tokenish<R: RngCore + ?Sized>(
    target_huffman_bytes: u32,
    rng: &mut R,
) -> Result<Option<String>, PaddingError> {
    // ceil(target / 0.8), written without floating-point drift.
    let initial_chars = (u64::from(target_huffman_bytes) * 5).div_ceil(4).max(1);
    let initial_chars = usize::try_from(initial_chars).map_err(|_| PaddingError::TooLarge)?;

    let mut bytes = Vec::new();
    let capacity = initial_chars
        .checked_add(TOKENISH_MAX_ADJUSTMENTS)
        .ok_or(PaddingError::TooLarge)?;
    bytes.try_reserve_exact(capacity)?;
    let mut entropy = [0_u8; 256];
    while bytes.len() < initial_chars {
        if rng.try_fill_bytes(&mut entropy).is_err() {
            return Ok(None);
        }
        for byte in entropy {
            if byte >= BASE62_REJECTION_LIMIT {
                continue;
            }
            bytes.push(BASE62[usize::from(byte) % BASE62.len()]);
            if bytes.len() == initial_chars {
                break;
            }
        }
    }

    // Every byte came from BASE62, hence this conversion cannot fail.
    let mut padding = String::from_utf8(bytes).expect("base62 is valid UTF-8");
    let target = target_huffman_bytes as usize;
    let mut adjust = b'X';
    for _ in 0..TOKENISH_MAX_ADJUSTMENTS {
        let current = hpack_huffman_encoded_len(padding.as_bytes());
        if current.abs_diff(target) <= TOKENISH_TOLERANCE_BYTES {
            return Ok(Some(padding));
        }

        if current < target {
            padding.push(adjust as char);
            adjust = if adjust == b'X' { b'Z' } else { b'X' };
        } else if padding.len() > 1 {
            padding.pop();
        } else {
            return Ok(Some(padding));
        }
    }

    Ok(Some(padding))
}

fn hpack_huffman_encoded_len(input: &[u8]) -> usize {
    let bits: usize = input
        .iter()
        .map(|byte| usize::from(HPACK_HUFFMAN_CODE_LENGTHS[usize::from(*byte)]))
        .sum();
    bits.div_ceil(8)
}

// RFC 7541 Appendix B. Keeping the byte-length table local avoids pulling a
// second HPACK encoder into the transport solely to size padding.
const HPACK_HUFFMAN_CODE_LENGTHS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[cfg(test)]
mod tests {
    use std::io;

    use rand::{rngs::mock::StepRng, Error, RngCore};

    use super::*;

    #[test]
    fn xhttp_range_draw_is_exact_or_half_open() {
        let mut rng = StepRng::new(0, 1);
        assert_eq!(
            draw_range(NormalizedRange::exact(77), &mut rng).unwrap(),
            77
        );
        for _ in 0..1_000 {
            let value = draw_range(NormalizedRange { from: 10, to: 20 }, &mut rng).unwrap();
            assert!((10..20).contains(&value));
        }
    }

    #[test]
    fn xhttp_padding_repeat_x_has_exact_wire_length() {
        let mut rng = StepRng::new(0, 0);
        assert_eq!(
            generate_padding(XhttpPaddingMethod::RepeatX, 5, &mut rng).unwrap(),
            "XXXXX"
        );
        assert_eq!(hpack_huffman_encoded_len("XZXZX".as_bytes()), "XZXZX".len());
    }

    #[test]
    fn xhttp_padding_tokenish_is_base62_and_targets_huffman_length() {
        let mut rng = StepRng::new(0x0123_4567_89ab_cdef, 0x1020_3040_5060_7080);
        let padding = generate_padding(XhttpPaddingMethod::Tokenish, 800, &mut rng).unwrap();
        assert!(padding.bytes().all(|byte| BASE62.contains(&byte)));
        assert!(hpack_huffman_encoded_len(padding.as_bytes()).abs_diff(800) <= 2);
    }

    #[test]
    fn xhttp_padding_tokenish_rng_failure_falls_back_to_repeat_x() {
        struct FailedRng;

        impl RngCore for FailedRng {
            fn next_u32(&mut self) -> u32 {
                0
            }

            fn next_u64(&mut self) -> u64 {
                0
            }

            fn fill_bytes(&mut self, _dest: &mut [u8]) {
                panic!("generate_tokenish must use the fallible RNG API")
            }

            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
                Err(Error::new(io::Error::other("injected RNG failure")))
            }
        }

        assert_eq!(
            generate_padding(XhttpPaddingMethod::Tokenish, 7, &mut FailedRng).unwrap(),
            "XXXXXXX"
        );
    }
}
