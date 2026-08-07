//! RFC 6455 client framing, sized to match gorilla/websocket.
//!
//! Xray writes through gorilla with `WriteBufferSize: 4*1024`, so a message
//! larger than 4096 payload bytes is split into continuation frames at exactly
//! that boundary. The boundary is observable on the wire, so it is part of the
//! shape rather than an implementation detail.
//!
//! On the read side message boundaries carry no meaning: the layer above is
//! VLESS, which wants a byte stream, so text, binary and continuation payloads
//! are concatenated and empty messages disappear.

use rand::RngCore;

use crate::TransportError;

/// Gorilla's write buffer, and therefore Xray's fragment size.
pub const MAX_FRAME_PAYLOAD: usize = 4096;

pub(crate) const OPCODE_CONTINUATION: u8 = 0x0;
pub(crate) const OPCODE_TEXT: u8 = 0x1;
pub(crate) const OPCODE_BINARY: u8 = 0x2;
pub(crate) const OPCODE_CLOSE: u8 = 0x8;
pub(crate) const OPCODE_PING: u8 = 0x9;
pub(crate) const OPCODE_PONG: u8 = 0xa;

const FIN: u8 = 0x80;
const RSV_MASK: u8 = 0x70;
const OPCODE_MASK: u8 = 0x0f;
const MASKED: u8 = 0x80;
const LENGTH_MASK: u8 = 0x7f;

/// A control frame's payload may not exceed 125 bytes (RFC 6455 §5.5), and a
/// data frame longer than this is a peer we do not want to allocate for.
const MAX_CONTROL_PAYLOAD: usize = 125;
const MAX_INBOUND_PAYLOAD: u64 = 64 * 1024 * 1024;

/// Encodes one write as a masked binary message, fragmenting at 4096 bytes.
///
/// An empty payload still produces one empty frame, matching gorilla's
/// `WriteMessage`.
pub fn encode_client_frames(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);

    if payload.is_empty() {
        encode_frame(&mut out, OPCODE_BINARY, true, &[]);
        return out;
    }

    let mut chunks = payload.chunks(MAX_FRAME_PAYLOAD).peekable();
    let mut first = true;
    while let Some(chunk) = chunks.next() {
        let opcode = if first {
            OPCODE_BINARY
        } else {
            OPCODE_CONTINUATION
        };
        encode_frame(&mut out, opcode, chunks.peek().is_none(), chunk);
        first = false;
    }

    out
}

pub(crate) fn encode_frame(out: &mut Vec<u8>, opcode: u8, fin: bool, payload: &[u8]) {
    out.push(if fin { FIN | opcode } else { opcode });

    let length = payload.len();
    if length < 126 {
        out.push(MASKED | length as u8);
    } else if let Ok(length) = u16::try_from(length) {
        out.push(MASKED | 126);
        out.extend_from_slice(&length.to_be_bytes());
    } else {
        out.push(MASKED | 127);
        out.extend_from_slice(&(length as u64).to_be_bytes());
    }

    // A fresh key per frame. Reusing one would be a distinguishing signal.
    let mut key = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut key);
    out.extend_from_slice(&key);

    out.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % 4]),
    );
}

/// What one decoded frame asks the connection to do.
#[derive(Debug)]
pub enum FrameEvent {
    /// Data for the layer above.
    Payload(Vec<u8>),
    /// A ping arrived; echo this payload back in a pong.
    Pong(Vec<u8>),
    /// The peer closed. No further frames are read.
    Close,
}

/// Accumulates bytes from the socket and yields one event per complete frame.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    consumed: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Decodes the next complete frame, or `None` when more bytes are needed.
    ///
    /// Empty data messages are skipped rather than surfaced: an empty
    /// `Payload` would read as end-of-stream to a caller filling a `ReadBuf`.
    pub fn next_event(&mut self) -> Result<Option<FrameEvent>, TransportError> {
        loop {
            let Some((frame, length)) = self.parse_frame()? else {
                self.compact();
                return Ok(None);
            };
            self.consumed += length;

            match frame.opcode {
                OPCODE_CLOSE => return Ok(Some(FrameEvent::Close)),
                OPCODE_PING => return Ok(Some(FrameEvent::Pong(frame.payload))),
                OPCODE_PONG => continue,
                OPCODE_TEXT | OPCODE_BINARY | OPCODE_CONTINUATION => {
                    if frame.payload.is_empty() {
                        continue;
                    }
                    return Ok(Some(FrameEvent::Payload(frame.payload)));
                }
                opcode => {
                    return Err(TransportError::WebSocketProtocol(format!(
                        "unknown opcode 0x{opcode:x}"
                    )))
                }
            }
        }
    }

    /// Drops the bytes already handed out, so a long-lived connection does not
    /// grow its buffer without bound.
    fn compact(&mut self) {
        if self.consumed == 0 {
            return;
        }
        self.buffer.drain(..self.consumed);
        self.consumed = 0;
    }

    fn parse_frame(&self) -> Result<Option<(DecodedFrame, usize)>, TransportError> {
        let bytes = &self.buffer[self.consumed..];
        if bytes.len() < 2 {
            return Ok(None);
        }

        if bytes[0] & RSV_MASK != 0 {
            return Err(TransportError::WebSocketProtocol(
                "reserved bit set with no extension negotiated".to_owned(),
            ));
        }
        // RFC 6455 §5.1: a server must not mask. Accepting one would mean
        // unmasking payload the server never masked.
        if bytes[1] & MASKED != 0 {
            return Err(TransportError::WebSocketProtocol(
                "server frames must not be masked".to_owned(),
            ));
        }

        let opcode = bytes[0] & OPCODE_MASK;
        let is_control = opcode & 0x8 != 0;
        let short_length = (bytes[1] & LENGTH_MASK) as usize;
        let (payload_length, header) = match short_length {
            126 => {
                if bytes.len() < 4 {
                    return Ok(None);
                }
                (u64::from(u16::from_be_bytes([bytes[2], bytes[3]])), 4)
            }
            127 => {
                if bytes.len() < 10 {
                    return Ok(None);
                }
                let mut length = [0u8; 8];
                length.copy_from_slice(&bytes[2..10]);
                (u64::from_be_bytes(length), 10)
            }
            length => (length as u64, 2),
        };

        if is_control {
            if payload_length as usize > MAX_CONTROL_PAYLOAD {
                return Err(TransportError::WebSocketProtocol(
                    "control frame payload exceeds 125 bytes".to_owned(),
                ));
            }
            if bytes[0] & FIN == 0 {
                return Err(TransportError::WebSocketProtocol(
                    "control frames must not be fragmented".to_owned(),
                ));
            }
        } else if payload_length > MAX_INBOUND_PAYLOAD {
            return Err(TransportError::WebSocketProtocol(format!(
                "frame payload of {payload_length} bytes exceeds the 64 MiB limit"
            )));
        }

        let payload_length = payload_length as usize;
        let total = header + payload_length;
        if bytes.len() < total {
            return Ok(None);
        }

        Ok(Some((
            DecodedFrame {
                opcode,
                payload: bytes[header..total].to_vec(),
            },
            total,
        )))
    }
}

struct DecodedFrame {
    opcode: u8,
    payload: Vec<u8>,
}
