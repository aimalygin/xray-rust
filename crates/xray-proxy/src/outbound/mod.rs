//! Client-side handshakes that open a tunnel through an upstream proxy.

mod http;
mod socks;

pub use http::{
    encode_connect_request, http_connect, HttpAccount, HttpClientError,
    MAX_HTTP_CONNECT_RESPONSE_HEAD, MAX_HTTP_CREDENTIAL_LENGTH,
};
pub use socks::{
    decode_socks5_udp_reply, encode_socks5_udp_request, socks5_connect, socks5_udp_associate,
    validate_connect_target, SocksClientError, SocksUdpDrop, MAX_SOCKS_UDP_DATAGRAM_LENGTH,
};
