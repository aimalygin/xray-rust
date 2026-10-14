//! Bounded Shadowsocks 2022 client codecs. Compatibility: sing-shadowsocks
//! v0.2.7 locked by Xray-core v26.7.28; no AEAD-2017 or stream ciphers.
mod crypto;
mod stream;
mod udp;
pub use stream::ClientStream;
pub use udp::UdpSession;

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};
use xray_routing::{Network, Target, TargetAddr};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_KEYS: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 8192;
pub const MAX_RECORD_LENGTH: usize = 65535;
pub const MAX_UDP_WIRE_LENGTH: usize = 65507;
const TAG_LENGTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}
impl Cipher {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(invalid("unsupported Shadowsocks 2022 method")),
        }
    }
    pub fn key_len(self) -> usize {
        if self == Self::Aes128Gcm {
            16
        } else {
            32
        }
    }
}

/// Redacted and zeroized PSKs, including bounded AES identity chains.
pub struct Method {
    cipher: Cipher,
    keys: Vec<Zeroizing<Vec<u8>>>,
}
impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shadowsocks2022Method")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}
impl Method {
    pub fn new(name: &str, password: &str) -> io::Result<Self> {
        let cipher = Cipher::parse(name)?;
        if password.is_empty() || password.len() > MAX_PASSWORD_LENGTH {
            return Err(invalid("invalid Shadowsocks 2022 key length"));
        }
        let mut keys = Vec::new();
        for encoded in password.split(':') {
            if keys.len() == MAX_KEYS {
                return Err(invalid("too many Shadowsocks 2022 identity keys"));
            }
            let mut key = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .map_err(|_| invalid("invalid Shadowsocks 2022 key encoding"))?,
            );
            if key.len() < cipher.key_len() {
                return Err(invalid("invalid Shadowsocks 2022 key length"));
            }
            if key.len() > cipher.key_len() {
                // Exact locked peer normalization. This is not EVP_BytesToKey.
                let mut digest = Sha256::digest(&*key);
                key.zeroize();
                key.extend_from_slice(&digest[..cipher.key_len()]);
                digest[..].zeroize();
            }
            keys.push(key);
        }
        if cipher == Cipher::ChaCha20Poly1305 && keys.len() != 1 {
            return Err(invalid("ChaCha20 does not support identity keys"));
        }
        Ok(Self { cipher, keys })
    }
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }
    fn psk(&self) -> &[u8] {
        self.keys.last().expect("validated nonempty keys")
    }
    pub fn validate_target(target: &Target) -> io::Result<()> {
        encode_address(target).map(|_| ())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| invalid("system time precedes Unix epoch"))
}
fn check_time(timestamp: u64, now: u64) -> io::Result<()> {
    if timestamp.abs_diff(now) > 30 {
        Err(invalid("Shadowsocks 2022 timestamp outside window"))
    } else {
        Ok(())
    }
}
fn encode_address(target: &Target) -> io::Result<Vec<u8>> {
    if target.port == 0 {
        return Err(invalid("Shadowsocks 2022 target port is zero"));
    }
    let mut bytes = Vec::with_capacity(259);
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || domain.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(invalid("invalid Shadowsocks 2022 target domain"));
            }
            bytes.extend_from_slice(&[3, domain.len() as u8]);
            bytes.extend_from_slice(domain.as_bytes());
        }
    }
    bytes.extend_from_slice(&target.port.to_be_bytes());
    Ok(bytes)
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(invalid("truncated Shadowsocks 2022 message"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn target(&mut self) -> io::Result<Target> {
        let addr = match self.u8()? {
            1 => TargetAddr::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).unwrap()).into()),
            4 => {
                TargetAddr::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(self.take(16)?).unwrap()).into())
            }
            3 => {
                let n = self.u8()? as usize;
                TargetAddr::Domain(
                    std::str::from_utf8(self.take(n)?)
                        .map_err(|_| invalid("invalid Shadowsocks 2022 domain"))?
                        .to_owned(),
                )
            }
            _ => return Err(invalid("invalid Shadowsocks 2022 address type")),
        };
        let target = Target::new(addr, self.u16()?, Network::Udp);
        Method::validate_target(&target)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    pub(super) fn fixtures() -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/v08/protocol-primitives.json"
        ))
        .unwrap();
        v["shadowsocks2022"].as_array().unwrap().clone()
    }
    #[test]
    fn keys_and_method_bounds_are_redacted() {
        for name in ["aes-128-gcm", "chacha20-poly1305", "unknown-secret"] {
            assert!(Cipher::parse(name).is_err());
        }
        for password in [
            "synthetic-secret".to_owned(),
            STANDARD.encode([1; 15]),
            "A".repeat(MAX_PASSWORD_LENGTH + 1),
        ] {
            let e = Method::new("2022-blake3-aes-128-gcm", &password).unwrap_err();
            assert!(!e.to_string().contains(&password));
        }
        let key = STANDARD.encode([1; 32]);
        assert!(Method::new("2022-blake3-chacha20-poly1305", &format!("{key}:{key}")).is_err());
        assert!(Method::new(
            "2022-blake3-aes-256-gcm",
            &[key.as_str(); MAX_KEYS + 1].join(":")
        )
        .is_err());
        let method = Method::new("2022-blake3-aes-256-gcm", &key).unwrap();
        assert!(!format!("{method:?}").contains(&key));
    }
}
