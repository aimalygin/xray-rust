mod http;
mod socks;

pub use http::{parse_http_connect, HttpParseError};
pub use socks::{
    encode_socks5_udp_datagram, negotiate_socks5, negotiate_socks5_no_auth, parse_socks5_connect,
    parse_socks5_request, parse_socks5_request_message, parse_socks5_udp_datagram,
    write_socks5_failure, write_socks5_success, write_socks5_success_with_bind, SocksAccount,
    SocksCommand, SocksInboundAuth, SocksParseError, SocksRequest, SocksUdpDatagram,
    MAX_SOCKS_CREDENTIAL_LENGTH,
};
pub(crate) use socks::{
    encode_target_addr, read_socks5_address, AddressReadError, METHOD_NONE_ACCEPTABLE,
    METHOD_NO_AUTH, METHOD_PASSWORD, PASSWORD_AUTH_SUCCESS, PASSWORD_AUTH_VERSION,
};
