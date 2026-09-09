use std::fmt;

use base64::{engine::general_purpose, Engine};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("WireGuard key must encode exactly 32 bytes in hex or base64")]
pub struct KeyError;

/// Decoded key material with redacted Debug and zeroization on drop.
///
/// Follows Xray's hex/standard-base64/URL-base64 input spellings, but rejects
/// decoded lengths other than 32 before engine construction. Key role checks
/// (including unusable public points) belong to the selected crypto engine.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial(Zeroizing<[u8; 32]>);

impl KeyMaterial {
    pub fn parse(input: &str) -> Result<Self, KeyError> {
        let mut output = Zeroizing::new([0u8; 32]);
        if input.len() == 64 {
            for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
                let high = hex_digit(pair[0]).ok_or(KeyError)?;
                let low = hex_digit(pair[1]).ok_or(KeyError)?;
                output[index] = (high << 4) | low;
            }
            return Ok(Self(output));
        }
        // A 32-byte key has 43 base64 characters plus at most one '='.
        // Check before decoding, avoiding allocation based on input length.
        if input.len() != 43 && input.len() != 44 {
            return Err(KeyError);
        }
        let input = input.strip_suffix('=').unwrap_or(input);
        let engine = if input.contains(['+', '/']) {
            &general_purpose::STANDARD_NO_PAD
        } else {
            &general_purpose::URL_SAFE_NO_PAD
        };
        let written = engine
            .decode_slice(input, &mut output[..])
            .map_err(|_| KeyError)?;
        if written != 32 {
            return Err(KeyError);
        }
        Ok(Self(output))
    }

    /// Explicit secret access for passing to the crypto engine. Do not log it.
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaterial(<redacted>)")
    }
}
