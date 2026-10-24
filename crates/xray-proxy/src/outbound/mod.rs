//! Client-side handshakes that open a tunnel through an upstream proxy.

mod socks;

pub use socks::{socks5_connect, validate_connect_target, SocksClientError};
