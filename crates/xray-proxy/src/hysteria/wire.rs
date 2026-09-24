use std::fmt;

use thiserror::Error;

pub const TCP_REQUEST_ID: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
/// Codec/reassembly ceiling. The IP adapter may impose a smaller UDP limit.
pub const MAX_UDP_PAYLOAD: usize = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("incomplete Hysteria message")]
    Incomplete,
    #[error("unexpected Hysteria stream frame type")]
    FrameType,
    #[error("invalid Hysteria address length or encoding")]
    Address,
    #[error("Hysteria response message exceeds its limit")]
    MessageTooLong,
    #[error("Hysteria padding exceeds its limit")]
    PaddingTooLong,
    #[error("invalid Hysteria UDP payload length")]
    PayloadLength,
    #[error("invalid Hysteria UDP fragment metadata")]
    Fragment,
    #[error("QUIC datagram limit cannot carry this Hysteria message")]
    DatagramLimit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpRequest<'a> {
    /// Wire address only; the outbound must validate host:port before dialing.
    pub address: &'a str,
    pub padding: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpResponse<'a> {
    /// As in Xray, only zero indicates success; every nonzero value is failure.
    pub status: u8,
    /// Opaque server bytes, deliberately omitted from Debug and error text.
    pub message: &'a [u8],
    pub padding: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: &'a str,
    pub payload: &'a [u8],
}

impl fmt::Debug for TcpRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpRequest")
            .field("address_length", &self.address.len())
            .field("padding_length", &self.padding.len())
            .finish()
    }
}

impl fmt::Debug for TcpResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpResponse")
            .field("status", &self.status)
            .field("message_length", &self.message.len())
            .field("padding_length", &self.padding.len())
            .finish()
    }
}

impl fmt::Debug for UdpMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpMessage")
            .field("session_id", &self.session_id)
            .field("packet_id", &self.packet_id)
            .field("fragment_id", &self.fragment_id)
            .field("fragment_count", &self.fragment_count)
            .field("address_length", &self.address.len())
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let tail = &self.input[self.position..];
        let bytes = tail.get(..length).ok_or(WireError::Incomplete)?;
        self.position += length;
        Ok(bytes)
    }

    fn varint(&mut self) -> Result<u64, WireError> {
        let first = self.take(1)?[0];
        let width = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(width - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn bounded_bytes(&mut self, limit: usize, error: WireError) -> Result<&'a [u8], WireError> {
        let length = self.varint()?;
        // Check before casting (including on 32-bit targets) or allocating.
        if length > limit as u64 {
            return Err(error);
        }
        self.take(length as usize)
    }

    fn address(&mut self) -> Result<&'a str, WireError> {
        let bytes = self.bounded_bytes(MAX_ADDRESS_LENGTH, WireError::Address)?;
        let address = std::str::from_utf8(bytes).map_err(|_| WireError::Address)?;
        validate_address(address)?;
        Ok(address)
    }
}

fn validate_address(address: &str) -> Result<(), WireError> {
    if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
        return Err(WireError::Address);
    }
    Ok(())
}

fn varint_length(value: usize) -> usize {
    if value < 64 {
        1
    } else if value < 16384 {
        2
    } else {
        4
    }
}

// All callers pass lengths bounded by MAX_UDP_PAYLOAD or TCP_REQUEST_ID.
fn put_varint(output: &mut Vec<u8>, value: usize) {
    match varint_length(value) {
        1 => output.push(value as u8),
        2 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        _ => output.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes()),
    }
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(output, bytes.len());
    output.extend_from_slice(bytes);
}

/// Includes the 0x401 stream type, which Xray's transport writes separately
/// from proxy/hysteria.WriteTCPRequest. Returned offset leaves application data
/// untouched. Accepts legal non-minimal QUIC varints, as Xray does.
pub fn decode_tcp_request(input: &[u8]) -> Result<(TcpRequest<'_>, usize), WireError> {
    let mut reader = Reader::new(input);
    if reader.varint()? != TCP_REQUEST_ID {
        return Err(WireError::FrameType);
    }
    let address = reader.address()?;
    let padding = reader.bounded_bytes(MAX_PADDING_LENGTH, WireError::PaddingTooLong)?;
    Ok((TcpRequest { address, padding }, reader.position))
}

pub fn encode_tcp_request(request: &TcpRequest<'_>) -> Result<Vec<u8>, WireError> {
    validate_address(request.address)?;
    if request.padding.len() > MAX_PADDING_LENGTH {
        return Err(WireError::PaddingTooLong);
    }
    let mut output = Vec::with_capacity(6 + request.address.len() + request.padding.len());
    put_varint(&mut output, TCP_REQUEST_ID as usize);
    put_bytes(&mut output, request.address.as_bytes());
    put_bytes(&mut output, request.padding);
    Ok(output)
}

pub fn decode_tcp_response(input: &[u8]) -> Result<(TcpResponse<'_>, usize), WireError> {
    let mut reader = Reader::new(input);
    let status = reader.take(1)?[0];
    let message = reader.bounded_bytes(MAX_MESSAGE_LENGTH, WireError::MessageTooLong)?;
    let padding = reader.bounded_bytes(MAX_PADDING_LENGTH, WireError::PaddingTooLong)?;
    Ok((
        TcpResponse {
            status,
            message,
            padding,
        },
        reader.position,
    ))
}

pub fn encode_tcp_response(response: &TcpResponse<'_>) -> Result<Vec<u8>, WireError> {
    if response.message.len() > MAX_MESSAGE_LENGTH {
        return Err(WireError::MessageTooLong);
    }
    if response.padding.len() > MAX_PADDING_LENGTH {
        return Err(WireError::PaddingTooLong);
    }
    let mut output = Vec::with_capacity(5 + response.message.len() + response.padding.len());
    output.push(response.status);
    put_bytes(&mut output, response.message);
    put_bytes(&mut output, response.padding);
    Ok(output)
}

impl UdpMessage<'_> {
    pub fn header_length(&self) -> usize {
        8 + varint_length(self.address.len()) + self.address.len()
    }

    pub(crate) fn validate(&self) -> Result<(), WireError> {
        validate_address(self.address)?;
        // The pinned Xray parser requires at least one payload byte.
        if self.payload.is_empty() || self.payload.len() > MAX_UDP_PAYLOAD {
            return Err(WireError::PayloadLength);
        }
        if self.fragment_count == 0
            || (self.fragment_count > 1 && self.fragment_id >= self.fragment_count)
        {
            return Err(WireError::Fragment);
        }
        Ok(())
    }
}

pub fn decode_udp_message(input: &[u8]) -> Result<UdpMessage<'_>, WireError> {
    let mut reader = Reader::new(input);
    let header = reader.take(8)?;
    let session_id = u32::from_be_bytes(header[..4].try_into().expect("four header bytes"));
    let packet_id = u16::from_be_bytes([header[4], header[5]]);
    let address = reader.address()?;
    let message = UdpMessage {
        session_id,
        packet_id,
        fragment_id: header[6],
        fragment_count: header[7],
        address,
        payload: &input[reader.position..],
    };
    message.validate()?;
    Ok(message)
}

pub fn encode_udp_message(message: &UdpMessage<'_>) -> Result<Vec<u8>, WireError> {
    message.validate()?;
    let mut output = Vec::with_capacity(message.header_length() + message.payload.len());
    // Xray's Serialize leaves these bytes for its transport; this codec owns
    // the entire datagram and must always write the actual session identifier.
    output.extend_from_slice(&message.session_id.to_be_bytes());
    output.extend_from_slice(&message.packet_id.to_be_bytes());
    output.push(message.fragment_id);
    output.push(message.fragment_count);
    put_bytes(&mut output, message.address.as_bytes());
    output.extend_from_slice(message.payload);
    Ok(output)
}

/// Split a complete message without copying its payload. The caller assigns
/// packet IDs per session and serializes each returned fragment separately.
pub fn fragment_udp_message<'a>(
    message: &UdpMessage<'a>,
    max_datagram_size: usize,
) -> Result<Vec<UdpMessage<'a>>, WireError> {
    message.validate()?;
    if message.fragment_count != 1 {
        return Err(WireError::Fragment);
    }
    let capacity = max_datagram_size
        .checked_sub(message.header_length())
        .filter(|capacity| *capacity > 0)
        .ok_or(WireError::DatagramLimit)?;
    let count = message.payload.len().div_ceil(capacity);
    let count = u8::try_from(count).map_err(|_| WireError::DatagramLimit)?;
    Ok(message
        .payload
        .chunks(capacity)
        .enumerate()
        .map(|(index, payload)| UdpMessage {
            fragment_id: index as u8,
            fragment_count: count,
            payload,
            ..*message
        })
        .collect())
}
