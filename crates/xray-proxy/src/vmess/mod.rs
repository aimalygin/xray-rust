//! AEAD-only VMess client primitives pinned to Xray-core v26.7.28.
mod crypto;
mod records;
mod split;
mod stream;
use rand::RngCore;
pub use split::{ClientReadHalf, ClientWriteHalf};
use std::{
    fmt, io,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};
pub use stream::ClientStream;
use xray_routing::{Network, Target, TargetAddr};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    ChaCha20Poly1305,
}
impl Cipher {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            "auto" | "" => Ok(Self::default()),
            _ => Err(invalid("unsupported VMess AEAD cipher")),
        }
    }
    fn wire(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::ChaCha20Poly1305 => 4,
        }
    }
}
impl Default for Cipher {
    fn default() -> Self {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Self::Aes128Gcm;
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq") {
            return Self::Aes128Gcm;
        }
        Self::ChaCha20Poly1305
    }
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub authenticated_length: bool,
    pub no_termination_signal: bool,
}
impl Options {
    fn wire(self) -> u8 {
        0x0d | if self.authenticated_length { 0x10 } else { 0 }
    }
}
pub struct Account {
    command_key: Zeroizing<[u8; 16]>,
    cipher: Cipher,
    options: Options,
}
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VMessAccount")
            .field("cipher", &self.cipher)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}
impl Account {
    pub fn new(id: &[u8; 16], cipher: Cipher, options: Options) -> Self {
        let mut material = Zeroizing::new(id.to_vec());
        material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        Self {
            command_key: crypto::md5(&material),
            cipher,
            options,
        }
    }
    pub fn validate_target(target: &Target) -> io::Result<()> {
        address(target).map(|_| ())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn random(bytes: &mut [u8]) -> io::Result<()> {
    rand::rngs::OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| invalid("VMess random source failed"))
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| invalid("VMess system time precedes epoch"))
}
fn address(target: &Target) -> io::Result<Vec<u8>> {
    if target.port == 0 {
        return Err(invalid("VMess target port is zero"));
    }
    let mut out = target.port.to_be_bytes().to_vec();
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            out.push(3);
            out.extend(ip.octets());
        }
        TargetAddr::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || domain.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(invalid("invalid VMess target domain"));
            }
            out.extend([2, domain.len() as u8]);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(out)
}
struct SessionKeys {
    request_key: Zeroizing<[u8; 16]>,
    request_iv: Zeroizing<[u8; 16]>,
    response_key: Zeroizing<[u8; 16]>,
    response_iv: Zeroizing<[u8; 16]>,
    response_marker: u8,
}
impl SessionKeys {
    fn from_entropy(entropy: &[u8; 33]) -> Self {
        let key: Zeroizing<[u8; 16]> = Zeroizing::new(entropy[..16].try_into().unwrap());
        let iv: Zeroizing<[u8; 16]> = Zeroizing::new(entropy[16..32].try_into().unwrap());
        Self {
            response_key: Zeroizing::new(crypto::sha256(&*key)[..16].try_into().unwrap()),
            response_iv: Zeroizing::new(crypto::sha256(&*iv)[..16].try_into().unwrap()),
            request_key: key,
            request_iv: iv,
            response_marker: entropy[32],
        }
    }
    fn request(
        &self,
        account: &Account,
        target: Option<&Target>,
        timestamp: u64,
        auth_random: &[u8; 4],
        connection_nonce: &[u8; 8],
        padding: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        if padding.len() > 15 {
            return Err(invalid("invalid VMess request padding"));
        }
        let mut plain = Zeroizing::new(vec![1]);
        plain.extend_from_slice(&*self.request_iv);
        plain.extend_from_slice(&*self.request_key);
        plain.extend([
            self.response_marker,
            account.options.wire(),
            ((padding.len() as u8) << 4) | account.cipher.wire(),
            0,
            target.map_or(3, |t| if t.network == Network::Tcp { 1 } else { 2 }),
        ]);
        if let Some(target) = target {
            plain.extend(address(target)?);
        }
        plain.extend_from_slice(padding);
        let hash = plain.iter().fold(0x811c9dc5u32, |h, b| {
            (h ^ u32::from(*b)).wrapping_mul(0x1000193)
        });
        plain.extend(hash.to_be_bytes());
        let auth = crypto::auth_id(&*account.command_key, timestamp, auth_random);
        let (aead, nonce) = crypto::header_aead(
            &*account.command_key,
            &*account.command_key,
            &[b"VMess Header AEAD Key_Length", &*auth, connection_nonce],
            &[b"VMess Header AEAD Nonce_Length", &*auth, connection_nonce],
        );
        let mut length = Zeroizing::new((plain.len() as u16).to_be_bytes().to_vec());
        aead.seal(&nonce, &*auth, &mut length)?;
        let (aead, nonce) = crypto::header_aead(
            &*account.command_key,
            &*account.command_key,
            &[b"VMess Header AEAD Key", &*auth, connection_nonce],
            &[b"VMess Header AEAD Nonce", &*auth, connection_nonce],
        );
        aead.seal(&nonce, &*auth, &mut plain)?;
        let mut wire = Zeroizing::new(auth.to_vec());
        wire.extend_from_slice(&length);
        wire.extend_from_slice(connection_nonce);
        wire.extend_from_slice(&plain);
        Ok(wire)
    }
}

#[cfg(test)]
mod tests;

/// Deterministic record entry point for the bounded sanitizer fuzz target.
#[cfg(feature = "fuzzing")]
pub fn fuzz_records(data: &[u8]) {
    let Some((&flags, mut data)) = data.split_first() else {
        return;
    };
    let cipher = if flags & 1 == 0 {
        Cipher::Aes128Gcm
    } else {
        Cipher::ChaCha20Poly1305
    };
    let (key, iv) = ([0x11; 16], [0x22; 16]);
    let mut records =
        records::Records::new(cipher, &key, &iv, (flags & 2 != 0).then_some((&key, &iv)));
    for _ in 0..128 {
        let n = records.size_bytes();
        if data.len() < n {
            return;
        }
        let mut length = data[..n].to_vec();
        data = &data[n..];
        let Ok((size, padding)) = records.decode_length(&mut length) else {
            return;
        };
        assert!(size <= 65535);
        if data.len() < size {
            return;
        }
        let mut body = data[..size].to_vec();
        data = &data[size..];
        if records.open(&mut body, padding).is_err() {
            return;
        }
    }
}
