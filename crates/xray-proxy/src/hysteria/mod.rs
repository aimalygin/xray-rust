//! Hysteria 2 wire primitives for the Xray-core v26.7.28 baseline.
//!
//! These codecs do not authenticate a connection, open sockets, or enable a
//! runtime outbound. The caller must authenticate HTTP/3 before proxy traffic.

mod reassembly;
mod wire;

pub use reassembly::{ReassembledDatagram, Reassembler, ReassemblyError};
pub use wire::{
    decode_tcp_request, decode_tcp_response, decode_udp_message, encode_tcp_request,
    encode_tcp_response, encode_udp_message, fragment_udp_message, TcpRequest, TcpResponse,
    UdpMessage, WireError, MAX_ADDRESS_LENGTH, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH,
    MAX_UDP_PAYLOAD, TCP_REQUEST_ID,
};
