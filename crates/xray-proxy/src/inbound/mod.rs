mod http;
mod socks;

pub use http::{parse_http_connect, HttpParseError};
pub use socks::{parse_socks5_connect, SocksParseError};
