use crate::{crypto_error, ConfigError};
use rand::{rngs::OsRng, RngCore};
use std::{io, time::Duration};

pub(crate) const MAX_PARTS: usize = 32;
pub(crate) const MAX_TOTAL: u32 = 65553;
pub(crate) const MAX_GAP_MS: u32 = 1000;
pub(crate) const MAX_TOTAL_GAP_MS: u32 = 5000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Padding(pub(crate) Vec<[u32; 3]>);

impl Padding {
    pub(crate) fn parse(parts: &[&str]) -> Result<Self, ConfigError> {
        if parts.len() > MAX_PARTS {
            return Err(ConfigError::Padding);
        }
        let mut values = Vec::with_capacity(parts.len());
        let (mut length, mut gaps) = (0, 0);
        for (index, part) in parts.iter().enumerate() {
            // Xray classifies padding tokens by their short encoded length.
            if part.len() >= 20 {
                return Err(ConfigError::Padding);
            }
            let fields: Vec<_> = part.split('-').collect();
            if fields.len() != 3 {
                return Err(ConfigError::Padding);
            }
            let mut item = [0; 3];
            for (dst, field) in item.iter_mut().zip(fields) {
                if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ConfigError::Padding);
                }
                *dst = field.parse::<u32>().map_err(|_| ConfigError::Padding)?;
            }
            if item[0] > 100 {
                return Err(ConfigError::Padding);
            }
            // RandBetween swaps reversed endpoints, then excludes the upper
            // endpoint unless both endpoints are equal.
            if item[1] > item[2] {
                item.swap(1, 2);
            }
            if index == 0 && (item[0] != 100 || item[1] < 35) {
                return Err(ConfigError::Padding);
            }
            if index % 2 == 0 {
                length = u32::checked_add(length, item[2]).ok_or(ConfigError::Padding)?;
                if length > MAX_TOTAL {
                    return Err(ConfigError::Padding);
                }
            } else {
                gaps = u32::checked_add(gaps, item[2]).ok_or(ConfigError::Padding)?;
                if item[2] > MAX_GAP_MS || gaps > MAX_TOTAL_GAP_MS {
                    return Err(ConfigError::Padding);
                }
            }
            values.push(item);
        }
        Ok(Self(values))
    }

    pub(crate) fn sample(&self) -> io::Result<PaddingPlan> {
        const DEFAULT: [[u32; 3]; 3] = [[100, 111, 1111], [75, 0, 111], [50, 0, 3333]];
        let parts = if self.0.is_empty() {
            DEFAULT.as_slice()
        } else {
            self.0.as_slice()
        };
        let mut plan = PaddingPlan {
            total: 0,
            lengths: Vec::new(),
            gaps: Vec::new(),
        };
        for (index, [probability, low, high]) in parts.iter().copied().enumerate() {
            let chosen = if between(0, 100)? <= probability {
                between(low, high)?
            } else {
                0
            };
            if index % 2 == 0 {
                plan.total += chosen as usize;
                plan.lengths.push(chosen as usize);
            } else {
                plan.gaps.push(Duration::from_millis(u64::from(chosen)));
            }
        }
        Ok(plan)
    }
}

pub(crate) struct PaddingPlan {
    pub(crate) total: usize,
    pub(crate) lengths: Vec<usize>,
    pub(crate) gaps: Vec<Duration>,
}

// Fallible entropy with rejection sampling. No panic or modulo bias, including
// a degenerate fixed range. Public endpoints are bounded during parsing.
fn between(low: u32, high: u32) -> io::Result<u32> {
    if low == high {
        return Ok(low);
    }
    let width = high - low;
    let limit = u32::MAX - u32::MAX % width;
    loop {
        let mut bytes = [0; 4];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| crypto_error())?;
        let value = u32::from_le_bytes(bytes);
        if value < limit {
            return Ok(low + value % width);
        }
    }
}
