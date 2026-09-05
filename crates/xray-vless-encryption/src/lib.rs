//! VLESS encryption client pinned to Xray-core v26.7.28.
//!
//! Supports bounded 1-RTT and 0-RTT sessions, one-to-eight chained NFS public
//! keys, configurable padding, and native/xorpub/random modes.
//! See `docs/vless-encryption-design.md` for the wire and lifecycle contract.

mod config;
mod crypto;
mod handshake;
mod padding;
mod session;
mod stream;

pub use config::{ClientConfig, ConfigError, Encryption, Rtt, XorMode};
pub use crypto::CipherSuite;
pub use session::Client;
pub use stream::EncryptedStream;

#[cfg(feature = "fuzzing")]
pub use stream::fuzzing;

use std::io;

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid VLESS encrypted peer data",
    )
}

fn crypto_error() -> io::Error {
    io::Error::other("VLESS encryption operation failed")
}
