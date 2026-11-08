use std::io;
use std::net::IpAddr;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};

use super::WireError;

const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 2;
const ADDR_IPV6: u8 = 3;
const XUDP_CMD_NEW: u8 = 1;
const XUDP_CMD_KEEP: u8 = 2;
const XUDP_CMD_DISCARD: u8 = 4;
const XUDP_OPT_DATA: u8 = 1;
const XUDP_NETWORK_UDP: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XudpPacket {
    pub source: Option<Target>,
    pub payload: Bytes,
}

pub fn encode_udp_packet(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    let len = u16::try_from(payload.len()).map_err(|_| WireError::PacketTooLong(payload.len()))?;
    let mut encoded = Vec::with_capacity(2 + payload.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub async fn read_udp_packet<R>(reader: &mut R) -> io::Result<Bytes>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u16().await?;
    let mut payload = vec![0; usize::from(len)];
    reader.read_exact(&mut payload).await?;
    Ok(Bytes::from(payload))
}

/// Reads VLESS UDP responses so that a `select!` may drop a read halfway:
/// the bytes a read took stay here, and only whole frames leave. The
/// one-shot readers below lose a frame's head when dropped after reading it,
/// which a transport that delivers a frame in pieces makes likely.
#[derive(Debug, Default)]
pub struct UdpResponseReader {
    buffer: BytesMut,
}

/// How much one read from the stream makes room for.
const RESPONSE_READ_CHUNK: usize = 16 * 1024;

impl UdpResponseReader {
    /// The next length-prefixed packet, as [`read_udp_packet`] reads it.
    pub async fn read_udp_packet<R>(&mut self, reader: &mut R) -> io::Result<Bytes>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if let Some((payload, used)) = decode_udp_packet(&self.buffer) {
                self.buffer.advance(used);
                return Ok(payload);
            }
            self.fill(reader).await?;
        }
    }

    /// The next XUDP packet with data, as [`read_xudp_packet`] reads it.
    pub async fn read_xudp_packet<R>(&mut self, reader: &mut R) -> io::Result<XudpPacket>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            while let Some((packet, used)) = decode_xudp_frame(&self.buffer)? {
                self.buffer.advance(used);
                if let Some(packet) = packet {
                    return Ok(packet);
                }
            }
            self.fill(reader).await?;
        }
    }

    /// One read into the buffer. `read_buf` reads nothing unless it
    /// completes, so dropping this loses no byte.
    async fn fill<R>(&mut self, reader: &mut R) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
    {
        self.buffer.reserve(RESPONSE_READ_CHUNK);
        if reader.read_buf(&mut self.buffer).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

/// A length-prefixed packet at the start of `input` and its length, or
/// `None` until it is whole.
fn decode_udp_packet(input: &[u8]) -> Option<(Bytes, usize)> {
    let head = input.get(..2)?;
    let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
    let payload = input.get(2..2 + len)?;
    Some((Bytes::copy_from_slice(payload), 2 + len))
}

/// One XUDP frame at the start of `input` and its length, or `None` until
/// it is whole. The packet is `None` for a frame [`read_xudp_packet`] skips:
/// one without data, with empty data, or a discard.
fn decode_xudp_frame(input: &[u8]) -> io::Result<Option<(Option<XudpPacket>, usize)>> {
    let Some(head) = input.get(..2) else {
        return Ok(None);
    };
    let metadata_len = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if metadata_len < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xudp metadata is shorter than mux header",
        ));
    }
    let Some(metadata) = input.get(2..2 + metadata_len) else {
        return Ok(None);
    };
    let command = metadata[2];
    if !matches!(command, XUDP_CMD_NEW | XUDP_CMD_KEEP | XUDP_CMD_DISCARD) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported xudp command {command}"),
        ));
    }
    let source = if metadata.len() > 4 && metadata[4] == XUDP_NETWORK_UDP {
        Some(decode_addr_port(&metadata[5..])?)
    } else {
        None
    };
    let header = 2 + metadata_len;
    if metadata[3] != XUDP_OPT_DATA {
        return Ok(Some((None, header)));
    }
    let Some((payload, used)) = decode_udp_packet(&input[header..]) else {
        return Ok(None);
    };
    let packet = (!payload.is_empty() && command != XUDP_CMD_DISCARD)
        .then_some(XudpPacket { source, payload });
    Ok(Some((packet, header + used)))
}

pub fn encode_xudp_new_packet(
    target: &Target,
    payload: &[u8],
    global_id: [u8; 8],
) -> Result<Vec<u8>, WireError> {
    let mut metadata = Vec::with_capacity(32);
    metadata.extend_from_slice(&[0, 0]);
    metadata.push(XUDP_CMD_NEW);
    metadata.push(XUDP_OPT_DATA);
    metadata.push(XUDP_NETWORK_UDP);
    encode_addr_port(target, &mut metadata)?;
    metadata.extend_from_slice(&global_id);
    encode_xudp_frame(metadata, payload)
}

pub fn encode_xudp_keep_packet(
    source: Option<&Target>,
    payload: &[u8],
) -> Result<Vec<u8>, WireError> {
    let mut metadata = Vec::with_capacity(24);
    metadata.extend_from_slice(&[0, 0]);
    metadata.push(XUDP_CMD_KEEP);
    metadata.push(XUDP_OPT_DATA);
    if let Some(source) = source {
        metadata.push(XUDP_NETWORK_UDP);
        encode_addr_port(source, &mut metadata)?;
    }
    encode_xudp_frame(metadata, payload)
}

pub async fn read_xudp_packet<R>(reader: &mut R) -> io::Result<XudpPacket>
where
    R: AsyncRead + Unpin,
{
    loop {
        let metadata_len = reader.read_u16().await?;
        if metadata_len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xudp metadata is shorter than mux header",
            ));
        }

        let mut metadata = vec![0; usize::from(metadata_len)];
        reader.read_exact(&mut metadata).await?;
        let command = metadata[2];
        let discard = command == XUDP_CMD_DISCARD;
        if !matches!(command, XUDP_CMD_NEW | XUDP_CMD_KEEP | XUDP_CMD_DISCARD) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported xudp command {command}"),
            ));
        }

        let source = if metadata.len() > 4 && metadata[4] == XUDP_NETWORK_UDP {
            Some(decode_addr_port(&metadata[5..])?)
        } else {
            None
        };

        if metadata[3] != XUDP_OPT_DATA {
            continue;
        }

        let payload = read_udp_packet(reader).await?;
        if payload.is_empty() || discard {
            continue;
        }

        return Ok(XudpPacket { source, payload });
    }
}

fn encode_xudp_frame(metadata: Vec<u8>, payload: &[u8]) -> Result<Vec<u8>, WireError> {
    let metadata_len =
        u16::try_from(metadata.len()).map_err(|_| WireError::PacketTooLong(metadata.len()))?;
    let payload_len =
        u16::try_from(payload.len()).map_err(|_| WireError::PacketTooLong(payload.len()))?;
    let mut encoded = Vec::with_capacity(2 + metadata.len() + 2 + payload.len());
    encoded.extend_from_slice(&metadata_len.to_be_bytes());
    encoded.extend_from_slice(&metadata);
    encoded.extend_from_slice(&payload_len.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn encode_addr_port(target: &Target, encoded: &mut Vec<u8>) -> Result<(), WireError> {
    encoded.extend_from_slice(&target.port.to_be_bytes());
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            encoded.push(ADDR_IPV4);
            encoded.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            encoded.push(ADDR_IPV6);
            encoded.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(domain) => {
            let len =
                u8::try_from(domain.len()).map_err(|_| WireError::DomainTooLong(domain.len()))?;
            encoded.push(ADDR_DOMAIN);
            encoded.push(len);
            encoded.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

fn decode_addr_port(input: &[u8]) -> io::Result<Target> {
    if input.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xudp address metadata is too short",
        ));
    }
    let port = u16::from_be_bytes([input[0], input[1]]);
    let addr = match input[2] {
        ADDR_IPV4 => {
            if input.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "xudp ipv4 metadata is too short",
                ));
            }
            TargetAddr::Ip(IpAddr::from([input[3], input[4], input[5], input[6]]))
        }
        ADDR_IPV6 => {
            if input.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "xudp ipv6 metadata is too short",
                ));
            }
            let octets = <[u8; 16]>::try_from(&input[3..19]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid xudp ipv6 metadata")
            })?;
            TargetAddr::Ip(IpAddr::from(octets))
        }
        ADDR_DOMAIN => {
            if input.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "xudp domain metadata is too short",
                ));
            }
            let len = usize::from(input[3]);
            if input.len() < 4 + len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "xudp domain metadata is too short",
                ));
            }
            let domain = std::str::from_utf8(&input[4..4 + len])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            TargetAddr::Domain(domain.to_owned())
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported xudp address type {other}"),
            ));
        }
    };

    Ok(Target::new(addr, port, Network::Udp))
}

#[cfg(test)]
mod response_reader_tests;

#[cfg(test)]
mod tests {
    use std::io;

    use super::{decode_addr_port, ADDR_DOMAIN};

    #[test]
    fn decode_addr_port_rejects_domain_without_length_byte() {
        let error = decode_addr_port(&[0, 53, ADDR_DOMAIN])
            .expect_err("truncated domain metadata should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
