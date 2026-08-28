//! XHTTP logical-session identifier generation.
//!
//! Xray uses UUID v4 when no custom table is configured. With a table it
//! draws one length from the configured half-open range and then selects every
//! byte independently and uniformly from that table. The random source is
//! injected by the transport so tests can pin the distribution boundary
//! without weakening production entropy.

use std::collections::TryReserveError;

use rand::RngCore;
use thiserror::Error;

use super::config::{session_id_room_is_large_enough, XhttpSessionIdConfig};

#[derive(Debug, Error)]
pub enum XhttpSessionIdError {
    #[error("XHTTP random source failed: {0}")]
    Random(#[source] rand::Error),
    #[error("XHTTP session ID allocation failed: {0}")]
    Allocation(#[from] TryReserveError),
    #[error("XHTTP custom session ID length does not fit this target")]
    LengthTooLarge,
    #[error("XHTTP custom session ID table does not fit the random selector")]
    TableTooLarge,
    #[error("XHTTP custom session ID table is not ASCII")]
    NonAsciiTable,
    #[error("XHTTP custom session ID length must be positive")]
    NonPositiveLength,
    #[error("XHTTP custom session ID length range has descending bounds")]
    DescendingRange,
    #[error("XHTTP custom session ID table or length is too small")]
    InsufficientEntropy,
}

pub fn generate_session_id<R: RngCore + ?Sized>(
    config: &XhttpSessionIdConfig,
    rng: &mut R,
) -> Result<String, XhttpSessionIdError> {
    if config.table.is_empty() {
        return generate_uuid_v4(rng);
    }
    if !config.table.is_ascii() {
        return Err(XhttpSessionIdError::NonAsciiTable);
    }
    if config.length.from == 0 || config.length.to == 0 {
        return Err(XhttpSessionIdError::NonPositiveLength);
    }
    if config.length.from > i32::MAX as u32 || config.length.to > i32::MAX as u32 {
        return Err(XhttpSessionIdError::LengthTooLarge);
    }
    if config.length.from > config.length.to {
        return Err(XhttpSessionIdError::DescendingRange);
    }
    if !session_id_room_is_large_enough(config.table.len(), config.length) {
        return Err(XhttpSessionIdError::InsufficientEntropy);
    }

    let length = draw_length(config, rng)?;
    let length = usize::try_from(length).map_err(|_| XhttpSessionIdError::LengthTooLarge)?;
    let table = config.table.as_bytes();
    let table_len = u64::try_from(table.len()).map_err(|_| XhttpSessionIdError::TableTooLarge)?;

    let mut id = Vec::new();
    id.try_reserve_exact(length)?;
    for _ in 0..length {
        let index = draw_below(table_len, rng)?;
        let index = usize::try_from(index).map_err(|_| XhttpSessionIdError::TableTooLarge)?;
        id.push(table[index]);
    }

    Ok(String::from_utf8(id).expect("the table was checked as ASCII"))
}

fn draw_length<R: RngCore + ?Sized>(
    config: &XhttpSessionIdConfig,
    rng: &mut R,
) -> Result<u32, XhttpSessionIdError> {
    let range = config.length;
    if range.from == range.to {
        return Ok(range.from);
    }
    Ok(range.from + u32::try_from(draw_below(u64::from(range.to - range.from), rng)?).unwrap())
}

fn draw_below<R: RngCore + ?Sized>(upper: u64, rng: &mut R) -> Result<u64, XhttpSessionIdError> {
    debug_assert!(upper > 0);
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(XhttpSessionIdError::Random)?;
        let sample = u64::from_le_bytes(bytes);
        if sample >= threshold {
            return Ok(sample % upper);
        }
    }
}

fn generate_uuid_v4<R: RngCore + ?Sized>(rng: &mut R) -> Result<String, XhttpSessionIdError> {
    let mut bytes = [0_u8; 16];
    rng.try_fill_bytes(&mut bytes)
        .map_err(XhttpSessionIdError::Random)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut id = String::new();
    id.try_reserve_exact(36)?;
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        id.push(hex(byte >> 4));
        id.push(hex(byte & 0x0f));
    }
    Ok(id)
}

fn hex(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + nibble - 10),
        _ => unreachable!("nibble is masked to four bits"),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use rand::rngs::mock::StepRng;
    use rand::Error;

    use super::*;
    use crate::stream::xhttp::config::NormalizedRange;

    #[test]
    fn uuid_fallback_preserves_v4_version_variant_and_wire_shape() {
        let mut rng = StepRng::new(0x0706_0504_0302_0100, 0x0808_0808_0808_0808);
        let id = generate_session_id(&XhttpSessionIdConfig::default(), &mut rng).unwrap();

        assert_eq!(id, "00010203-0405-4607-8809-0a0b0c0d0e0f");
    }

    #[test]
    fn custom_ids_use_exact_length_and_only_the_normalized_table() {
        let config = XhttpSessionIdConfig {
            table: "AZ".to_owned(),
            length: NormalizedRange::exact(32),
        };
        let mut rng = StepRng::new(0, 1);
        let id = generate_session_id(&config, &mut rng).unwrap();

        assert_eq!(id.len(), 32);
        assert_eq!(id, "AZ".repeat(16));
    }

    #[test]
    fn custom_length_draw_is_half_open_and_fresh_ids_consume_fresh_entropy() {
        let config = XhttpSessionIdConfig {
            table: "0123456789".to_owned(),
            length: NormalizedRange { from: 10, to: 13 },
        };
        let mut rng = StepRng::new(0, 1);
        let first = generate_session_id(&config, &mut rng).unwrap();
        let second = generate_session_id(&config, &mut rng).unwrap();

        assert!((10..13).contains(&first.len()));
        assert!((10..13).contains(&second.len()));
        assert!(first.bytes().all(|byte| byte.is_ascii_digit()));
        assert!(second.bytes().all(|byte| byte.is_ascii_digit()));
        assert_ne!(first, second);
    }

    #[test]
    fn generator_fails_closed_for_mutated_invalid_normalized_config() {
        let mut rng = StepRng::new(0, 0);
        assert!(matches!(
            generate_session_id(
                &XhttpSessionIdConfig {
                    table: "é".to_owned(),
                    length: NormalizedRange::exact(31),
                },
                &mut rng,
            ),
            Err(XhttpSessionIdError::NonAsciiTable)
        ));
        assert!(matches!(
            generate_session_id(
                &XhttpSessionIdConfig {
                    table: "ab".to_owned(),
                    length: NormalizedRange::exact(0),
                },
                &mut rng,
            ),
            Err(XhttpSessionIdError::NonPositiveLength)
        ));
        assert!(matches!(
            generate_session_id(
                &XhttpSessionIdConfig {
                    table: "ab".to_owned(),
                    length: NormalizedRange::exact(30),
                },
                &mut rng,
            ),
            Err(XhttpSessionIdError::InsufficientEntropy)
        ));
        assert!(matches!(
            generate_session_id(
                &XhttpSessionIdConfig {
                    table: "ab".to_owned(),
                    length: NormalizedRange { from: 32, to: 31 },
                },
                &mut rng,
            ),
            Err(XhttpSessionIdError::DescendingRange)
        ));
    }

    #[test]
    fn random_source_failure_is_not_replaced_with_a_predictable_id() {
        struct FailedRng;

        impl RngCore for FailedRng {
            fn next_u32(&mut self) -> u32 {
                0
            }

            fn next_u64(&mut self) -> u64 {
                0
            }

            fn fill_bytes(&mut self, _dest: &mut [u8]) {
                panic!("session ID generation must use the fallible RNG API")
            }

            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
                Err(Error::new(io::Error::other("injected RNG failure")))
            }
        }

        assert!(matches!(
            generate_session_id(&XhttpSessionIdConfig::default(), &mut FailedRng),
            Err(XhttpSessionIdError::Random(_))
        ));
        assert!(matches!(
            generate_session_id(
                &XhttpSessionIdConfig {
                    table: "ab".to_owned(),
                    length: NormalizedRange::exact(31),
                },
                &mut FailedRng,
            ),
            Err(XhttpSessionIdError::Random(_))
        ));
    }
}
