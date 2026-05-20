mod http;
mod socks;

pub use http::{parse_http_connect, HttpParseError};
pub use socks::{
    negotiate_socks5_no_auth, parse_socks5_connect, parse_socks5_request, write_socks5_failure,
    write_socks5_success, SocksParseError,
};
