//! mKCP segments as Xray-core v26.10.31 encodes them: every field big-endian
//! after a conversation, a command and an option byte.

/// The command byte of a segment.
pub(super) const CMD_ACK: u8 = 0;
pub(super) const CMD_DATA: u8 = 1;
pub(super) const CMD_TERMINATE: u8 = 2;
pub(super) const CMD_PING: u8 = 3;

/// The option bit a side sets while it closes.
pub(super) const OPTION_CLOSE: u8 = 1;

/// Bytes a data segment adds to its payload.
pub(super) const DATA_OVERHEAD: u32 = 18;

/// The most numbers an ack segment carries.
const ACK_NUMBER_LIMIT: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DataSegment {
    pub(super) conv: u16,
    pub(super) option: u8,
    pub(super) timestamp: u32,
    pub(super) number: u32,
    pub(super) sending_next: u32,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AckSegment {
    pub(super) conv: u16,
    pub(super) option: u8,
    pub(super) receiving_window: u32,
    pub(super) receiving_next: u32,
    pub(super) timestamp: u32,
    pub(super) numbers: Vec<u32>,
    /// How many numbers fit, as `NewAckSegment` bounds it.
    pub(super) limit: usize,
}

/// A ping, a terminate, or any other command without a body of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CmdSegment {
    pub(super) conv: u16,
    pub(super) cmd: u8,
    pub(super) option: u8,
    pub(super) sending_next: u32,
    pub(super) receiving_next: u32,
    pub(super) peer_rto: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    Cmd(CmdSegment),
}

impl Segment {
    pub(super) fn conv(&self) -> u16 {
        match self {
            Self::Data(segment) => segment.conv,
            Self::Ack(segment) => segment.conv,
            Self::Cmd(segment) => segment.conv,
        }
    }

    /// Appends the encoded segment to `out`, as a peer sends it.
    #[cfg(test)]
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Data(segment) => segment.encode(out),
            Self::Ack(segment) => segment.encode(out),
            Self::Cmd(segment) => segment.encode(out),
        }
    }
}

impl DataSegment {
    #[cfg(test)]
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        encode_data(
            out,
            DataHeader {
                conv: self.conv,
                option: self.option,
                timestamp: self.timestamp,
                number: self.number,
                sending_next: self.sending_next,
            },
            &self.payload,
        );
    }
}

/// The fields of a data segment besides its payload.
#[derive(Debug, Clone, Copy)]
pub(super) struct DataHeader {
    pub(super) conv: u16,
    pub(super) option: u8,
    pub(super) timestamp: u32,
    pub(super) number: u32,
    pub(super) sending_next: u32,
}

/// Appends a data segment carrying `payload`, at most 8192 bytes.
pub(super) fn encode_data(out: &mut Vec<u8>, header: DataHeader, payload: &[u8]) {
    out.extend_from_slice(&header.conv.to_be_bytes());
    out.push(CMD_DATA);
    out.push(header.option);
    out.extend_from_slice(&header.timestamp.to_be_bytes());
    out.extend_from_slice(&header.number.to_be_bytes());
    out.extend_from_slice(&header.sending_next.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

impl AckSegment {
    /// An empty ack holding up to `limit` numbers, bounded to 1..=128.
    pub(super) fn new(limit: i64) -> Self {
        Self {
            conv: 0,
            option: 0,
            receiving_window: 0,
            receiving_next: 0,
            timestamp: 0,
            numbers: Vec::new(),
            limit: limit.clamp(1, ACK_NUMBER_LIMIT as i64) as usize,
        }
    }

    /// Keeps the later of the two timestamps.
    pub(super) fn put_timestamp(&mut self, timestamp: u32) {
        if timestamp.wrapping_sub(self.timestamp) < 0x7FFF_FFFF {
            self.timestamp = timestamp;
        }
    }

    pub(super) fn is_full(&self) -> bool {
        self.numbers.len() == self.limit
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(CMD_ACK);
        out.push(self.option);
        out.extend_from_slice(&self.receiving_window.to_be_bytes());
        out.extend_from_slice(&self.receiving_next.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        // At most 128 numbers go out; a parsed segment is not re-encoded.
        out.push(self.numbers.len() as u8);
        for number in &self.numbers {
            out.extend_from_slice(&number.to_be_bytes());
        }
    }
}

impl CmdSegment {
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_be_bytes());
        out.push(self.cmd);
        out.push(self.option);
        out.extend_from_slice(&self.sending_next.to_be_bytes());
        out.extend_from_slice(&self.receiving_next.to_be_bytes());
        out.extend_from_slice(&self.peer_rto.to_be_bytes());
    }
}

fn u32_at(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Every segment in a datagram, up to the first that does not parse, as
/// `KCPPacketReader` reads them.
pub(super) fn read_segments(mut buf: &[u8]) -> Vec<Segment> {
    let mut segments = Vec::new();
    while !buf.is_empty() {
        let Some((segment, rest)) = read_segment(buf) else {
            break;
        };
        segments.push(segment);
        buf = rest;
    }
    segments
}

fn read_segment(buf: &[u8]) -> Option<(Segment, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes([buf[0], buf[1]]);
    let cmd = buf[2];
    let option = buf[3];
    let buf = &buf[4..];
    match cmd {
        CMD_DATA => {
            // Xray wants a byte past the 14-byte header, so an empty data
            // segment that ends the datagram does not parse.
            if buf.len() < 15 {
                return None;
            }
            let length = usize::from(u16::from_be_bytes([buf[12], buf[13]]));
            let rest = &buf[14..];
            if rest.len() < length {
                return None;
            }
            Some((
                Segment::Data(DataSegment {
                    conv,
                    option,
                    timestamp: u32_at(buf),
                    number: u32_at(&buf[4..]),
                    sending_next: u32_at(&buf[8..]),
                    payload: rest[..length].to_vec(),
                }),
                &rest[length..],
            ))
        }
        CMD_ACK => {
            if buf.len() < 13 {
                return None;
            }
            let count = usize::from(buf[12]);
            let rest = &buf[13..];
            if rest.len() < count * 4 {
                return None;
            }
            let mut segment = AckSegment::new(ACK_NUMBER_LIMIT as i64);
            segment.conv = conv;
            segment.option = option;
            segment.receiving_window = u32_at(buf);
            segment.receiving_next = u32_at(&buf[4..]);
            segment.timestamp = u32_at(&buf[8..]);
            segment.numbers = rest[..count * 4].chunks_exact(4).map(u32_at).collect();
            Some((Segment::Ack(segment), &rest[count * 4..]))
        }
        _ => {
            if buf.len() < 12 {
                return None;
            }
            Some((
                Segment::Cmd(CmdSegment {
                    conv,
                    cmd,
                    option,
                    sending_next: u32_at(buf),
                    receiving_next: u32_at(&buf[4..]),
                    peer_rto: u32_at(&buf[8..]),
                }),
                &buf[12..],
            ))
        }
    }
}

#[cfg(test)]
mod tests;
