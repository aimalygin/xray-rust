use std::{fmt, str::FromStr};

use crate::padding::Padding;
use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use zeroize::Zeroizing;

pub(crate) const MAX_CONFIG_BYTES: usize = 16384;
pub(crate) const MAX_KEYS: usize = 8;

/// No raw encryption string or public key is included in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("unsupported VLESS encryption scheme")]
    Scheme,
    #[error("VLESS encryption supports native, xorpub, or random mode")]
    Mode,
    #[error("VLESS encryption requires 1rtt or 0rtt")]
    Rtt,
    #[error("VLESS encryption requires one to eight NFS public keys and bounded padding before the keys")]
    Shape,
    #[error("VLESS encryption padding exceeds its syntax, size, or delay limits")]
    Padding,
    #[error(
        "VLESS encryption requires a canonical unpadded base64url X25519 or ML-KEM-768 public key"
    )]
    PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XorMode {
    Native,
    XorPub,
    Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rtt {
    OneRtt,
    ZeroRtt,
}

/// A validated client configuration. Key bytes are never exposed through Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub(crate) mode: XorMode,
    pub(crate) public_keys: Vec<Zeroizing<Vec<u8>>>,
    pub(crate) rtt: Rtt,
    pub(crate) padding: Padding,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessEncryptionClient")
            .field("mode", &self.mode)
            .field("rtt", &self.rtt)
            .field("key_count", &self.public_keys.len())
            .field("public_keys", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Encryption {
    #[default]
    None,
    Mlkem768X25519Plus(ClientConfig),
}

impl Encryption {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn client(&self) -> Option<&ClientConfig> {
        match self {
            Self::None => None,
            Self::Mlkem768X25519Plus(config) => Some(config),
        }
    }
}

impl FromStr for Encryption {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "none" {
            return Ok(Self::None);
        }
        // Bound work before splitting or allocating decoded key storage.
        if value.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Shape);
        }
        let mut fields = value.split('.');
        if fields.next() != Some("mlkem768x25519plus") {
            return Err(ConfigError::Scheme);
        }
        let mode = match fields.next() {
            Some("native") => XorMode::Native,
            Some("xorpub") => XorMode::XorPub,
            Some("random") => XorMode::Random,
            _ => return Err(ConfigError::Mode),
        };
        let rtt = match fields.next() {
            Some("1rtt") => Rtt::OneRtt,
            Some("0rtt") => Rtt::ZeroRtt,
            _ => return Err(ConfigError::Rtt),
        };
        let rest: Vec<_> = fields.collect();
        let key_start = rest
            .iter()
            .position(|part| part.len() >= 20)
            .ok_or(ConfigError::Shape)?;
        let padding = Padding::parse(&rest[..key_start])?;
        let keys = &rest[key_start..];
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(ConfigError::Shape);
        }
        let public_keys = keys
            .iter()
            .map(|key| validate_key(key))
            .collect::<Result<_, _>>()?;
        Ok(Self::Mlkem768X25519Plus(ClientConfig {
            mode,
            public_keys,
            rtt,
            padding,
        }))
    }
}

fn validate_key(encoded: &str) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    if !matches!(encoded.len(), 43 | 1579) {
        return Err(ConfigError::PublicKey);
    }
    let public_key = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ConfigError::PublicKey)?,
    );
    match public_key.len() {
        32 => {
            // Reject low-order points before dialing. A fixed scalar is
            // solely a validation probe, never a handshake private key.
            let bytes: [u8; 32] = public_key.as_slice().try_into().unwrap();
            let shared = x25519_dalek::StaticSecret::from([0x42; 32])
                .diffie_hellman(&x25519_dalek::PublicKey::from(bytes));
            if !shared.was_contributory() {
                return Err(ConfigError::PublicKey);
            }
        }
        1184 => {
            // AWS-LC's raw-key constructor only checks length. Reject
            // noncanonical 12-bit coefficients before dialing (FIPS 203
            // encapsulation-key modulus check, q = 3329).
            if public_key[..1152].chunks_exact(3).any(|p| {
                (u16::from(p[0]) | (u16::from(p[1] & 15) << 8)) >= 3329
                    || ((u16::from(p[1]) >> 4) | (u16::from(p[2]) << 4)) >= 3329
            }) {
                return Err(ConfigError::PublicKey);
            }
            EncapsulationKey::new(&ML_KEM_768, &public_key).map_err(|_| ConfigError::PublicKey)?;
        }
        _ => return Err(ConfigError::PublicKey),
    }
    Ok(public_key)
}
