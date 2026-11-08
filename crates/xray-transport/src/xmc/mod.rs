//! The `xmc` finalmask of Xray-core v26.10.31: a TCP carrier dressed as a
//! Minecraft 26.1.2 login. The client sends a handshake and a Login Start
//! for one of its profiles, checks that the server's RSA key is the one the
//! password derives, and sends a shared secret and the password under it.
//! Both sides then switch to AES-128-CFB8. Once the server confirms the
//! profile, a padding schedule copies the lengths of the rest of a login,
//! and the proxied bytes travel in configuration-state custom payload
//! packets.
mod cfb8;
mod handshake;
mod padding;
mod proto;
mod rsa;
mod stream;
#[cfg(test)]
mod testing;

use crate::BoxedTransportStream;
use rand::Rng;
use std::{fmt, io, net::SocketAddr, time::Duration};
pub use stream::XmcStream;

/// A profile the client logs in as. The server must hold the same one, as
/// the session server signed it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct XmcProfile {
    pub username: String,
    pub uuid: [u8; 16],
    pub textures_value: String,
    pub textures_signature: String,
}

/// The mask's settings, with the public key the password derives.
#[derive(Clone)]
pub struct XmcConfig {
    hostname: String,
    profiles: Vec<XmcProfile>,
    password: String,
    key: rsa::PublicKey,
}

impl fmt::Debug for XmcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XmcConfig")
            .field("hostname", &self.hostname)
            .field("profiles", &self.profiles)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl XmcConfig {
    /// `XMC.Build`: profiles and a password are required, and the password
    /// derives the server's RSA key, which takes a moment.
    pub fn new(
        hostname: impl Into<String>,
        profiles: Vec<XmcProfile>,
        password: impl Into<String>,
    ) -> io::Result<Self> {
        let password = password.into();
        if profiles.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "minecraft profiles are required",
            ));
        }
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty password",
            ));
        }
        Ok(Self {
            key: rsa::derived_public_key(&password),
            hostname: hostname.into(),
            profiles,
            password,
        })
    }
}

/// Xray's `handshakeTimeout`: the login's deadline.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// Logs in over `inner`, a carrier whose remote end is `remote`, as one of
/// the profiles chosen at random, and returns the carrier for the proxied
/// bytes.
pub async fn connect(
    inner: BoxedTransportStream,
    config: &XmcConfig,
    remote: SocketAddr,
) -> io::Result<XmcStream> {
    let profile = &config.profiles[rand::thread_rng().gen_range(0..config.profiles.len())];
    let schedule = padding::client_schedule();
    let mut conn = proto::Conn::new(inner);
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake::client(&mut conn, config, remote, profile, &schedule),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xmc login timed out"))??;
    XmcStream::new(conn)
}
