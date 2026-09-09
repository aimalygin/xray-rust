use std::fmt;
use std::time::{Duration, Instant};

use super::{UdpMessage, WireError, MAX_UDP_PAYLOAD};

/// One completed UDP payload; Debug never includes traffic or destination data.
#[derive(Clone, PartialEq, Eq)]
pub struct ReassembledDatagram {
    pub session_id: u32,
    pub address: String,
    pub payload: Vec<u8>,
}

impl fmt::Debug for ReassembledDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReassembledDatagram")
            .field("session_id", &self.session_id)
            .field("address_length", &self.address.len())
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReassemblyError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("Hysteria datagram belongs to another session")]
    Session,
    #[error("inconsistent Hysteria fragments")]
    Conflict,
    #[error("Hysteria reassembly payload budget exceeded")]
    Budget,
    #[error("invalid Hysteria reassembly limits")]
    Limits,
}

struct PartialPacket {
    packet_id: u16,
    address: String,
    first_seen: Instant,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    size: usize,
}

/// Bound to one live UDP session on one authenticated QUIC connection.
///
/// Keeps at most one incomplete packet, like the pinned Xray Defragger. A new
/// packet ID discards the previous partial packet. Addresses/counts must agree,
/// duplicates do not extend the deadline, and payload bytes are copied into
/// exactly owned buffers (never retaining an oversized network read buffer).
/// The runtime must cap live sessions globally and call `expire` on its timer.
pub struct Reassembler {
    session_id: u32,
    max_payload: usize,
    timeout: Duration,
    partial: Option<PartialPacket>,
}

impl Reassembler {
    pub fn new(
        session_id: u32,
        max_payload: usize,
        timeout: Duration,
    ) -> Result<Self, ReassemblyError> {
        if max_payload == 0 || max_payload > MAX_UDP_PAYLOAD || timeout.is_zero() {
            return Err(ReassemblyError::Limits);
        }
        Ok(Self {
            session_id,
            max_payload,
            timeout,
            partial: None,
        })
    }

    pub fn buffered_payload_bytes(&self) -> usize {
        self.partial.as_ref().map_or(0, |partial| partial.size)
    }

    pub fn expire(&mut self, now: Instant) {
        if self.partial.as_ref().is_some_and(|partial| {
            now.saturating_duration_since(partial.first_seen) >= self.timeout
        }) {
            self.partial = None;
        }
    }

    pub fn clear(&mut self) {
        self.partial = None;
    }

    pub fn feed(
        &mut self,
        message: &UdpMessage<'_>,
        now: Instant,
    ) -> Result<Option<ReassembledDatagram>, ReassemblyError> {
        self.expire(now);
        message.validate()?;
        if message.session_id != self.session_id {
            return Err(ReassemblyError::Session);
        }
        if message.payload.len() > self.max_payload {
            self.clear();
            return Err(ReassemblyError::Budget);
        }
        if message.fragment_count == 1 {
            self.clear();
            return Ok(Some(ReassembledDatagram {
                session_id: self.session_id,
                address: message.address.to_owned(),
                payload: message.payload.to_vec(),
            }));
        }

        if self
            .partial
            .as_ref()
            .is_none_or(|partial| partial.packet_id != message.packet_id)
        {
            self.partial = Some(PartialPacket {
                packet_id: message.packet_id,
                address: message.address.to_owned(),
                first_seen: now,
                fragments: vec![None; usize::from(message.fragment_count)],
                received: 0,
                size: 0,
            });
        }
        let partial = self.partial.as_mut().expect("partial packet initialized");
        if partial.address != message.address
            || partial.fragments.len() != usize::from(message.fragment_count)
        {
            self.clear();
            return Err(ReassemblyError::Conflict);
        }
        let slot = &mut partial.fragments[usize::from(message.fragment_id)];
        if let Some(existing) = slot {
            if existing.as_slice() == message.payload {
                return Ok(None);
            }
            self.clear();
            return Err(ReassemblyError::Conflict);
        }
        if message.payload.len() > self.max_payload - partial.size {
            self.clear();
            return Err(ReassemblyError::Budget);
        }
        *slot = Some(message.payload.to_vec());
        partial.size += message.payload.len();
        partial.received += 1;
        if partial.received != partial.fragments.len() {
            return Ok(None);
        }
        let partial = self.partial.take().expect("complete partial packet");
        let mut payload = Vec::with_capacity(partial.size);
        for fragment in partial.fragments {
            payload.extend_from_slice(&fragment.expect("every fragment received"));
        }
        Ok(Some(ReassembledDatagram {
            session_id: self.session_id,
            address: partial.address,
            payload,
        }))
    }
}
