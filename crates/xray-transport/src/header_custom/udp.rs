//! Stateful UDP prefixes and standalone client handshakes.
use super::{evaluate_item, match_item, measure_item, Context, CustomItem};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::Instant;

/// The client and server sequences of a `header-custom` UDP mask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderCustomUdpConfig {
    pub standalone: bool,
    pub client: Vec<CustomItem>,
    pub server: Vec<CustomItem>,
}

#[cfg(test)]
mod tests;

const TTL: Duration = Duration::from_secs(5);
const MAX_HEADER: usize = 4096;
type Vars = HashMap<String, Vec<u8>>;

pub(crate) enum Write {
    Packet(Vec<u8>),
    Handshake(Vec<u8>),
    Waiting,
    Drop,
}

pub(crate) struct UdpHeader {
    config: Arc<HeaderCustomUdpConfig>,
    write_size: Option<usize>,
    read_size: usize,
    states: HashMap<SocketAddr, (Instant, Vars)>,
    // Xray retains the last successfully matched variables as a write fallback.
    last_received: Vars,
    waiter: Option<(SocketAddr, Vars)>,
}

impl UdpHeader {
    pub(crate) fn receive_limit(&self) -> usize {
        if self.config.standalone {
            MAX_HEADER
        } else {
            usize::MAX
        }
    }

    pub(crate) fn waiting(&self) -> bool {
        self.waiter.is_some()
    }

    /// Forgets a standalone request that is no longer awaited.
    pub(crate) fn abandon(&mut self) {
        self.waiter = None;
    }

    /// What a prefix adds to every datagram; nothing in standalone mode.
    pub(crate) fn prefix_len(&self) -> usize {
        self.write_size.unwrap_or(0)
    }

    pub(crate) fn new(config: Arc<HeaderCustomUdpConfig>) -> io::Result<Self> {
        let invalid = |error| io::Error::new(io::ErrorKind::InvalidInput, error);
        let mut saved_sizes = HashMap::new();
        for item in &config.client {
            // collectSavedUDPSizes ignores items it cannot measure.
            let _ = measure_item(item, &mut saved_sizes);
        }
        let measure = |items: &[CustomItem], mut sizes: HashMap<String, usize>| {
            let mut total = 0usize;
            for item in items {
                let size = measure_item(item, &mut sizes).map_err(invalid)?;
                total = total
                    .checked_add(size)
                    .filter(|n| *n <= MAX_HEADER)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "UDP header exceeds 4096 bytes")
                    })?;
            }
            Ok::<_, io::Error>(total)
        };
        let write_size = if config.standalone {
            None
        } else {
            Some(measure(&config.client, HashMap::new())?)
        };
        let read_size = measure(&config.server, saved_sizes)?;
        Ok(Self {
            config,
            write_size,
            read_size,
            states: HashMap::new(),
            last_received: HashMap::new(),
            waiter: None,
        })
    }

    fn expire(&mut self, now: Instant) {
        self.states.retain(|_, (expires, _)| now <= *expires);
    }

    pub(crate) fn write(
        &mut self,
        payload: &[u8],
        local: Option<SocketAddr>,
        peer: SocketAddr,
        now: Instant,
    ) -> Write {
        self.expire(now);
        if self.config.standalone {
            if self.waiter.is_some() {
                return Write::Waiting;
            }
            if self.states.contains_key(&peer) {
                return Write::Packet(payload.to_vec());
            }
        }
        let mut context = Context::with_addresses(local, Some(peer));
        if !self.config.standalone {
            context.vars = self
                .states
                .get(&peer)
                .map(|(_, vars)| vars)
                .unwrap_or(&self.last_received)
                .clone();
        }
        let mut header = Vec::new();
        for item in &self.config.client {
            // Skip evaluating an item that cannot fit. Xray measures a prefix
            // sequence when it dials but never a standalone one, so an item
            // that cannot be measured (a computed pad length) is evaluated.
            if let Ok(length) = measure_item(item, &mut context.sizes()) {
                if length > MAX_HEADER.saturating_sub(header.len()) {
                    return Write::Drop;
                }
            }
            let Ok(bytes) = evaluate_item(item, &mut context) else {
                return Write::Drop;
            };
            if bytes.len() > MAX_HEADER.saturating_sub(header.len()) {
                return Write::Drop;
            }
            header.extend(bytes);
        }
        if self.config.standalone {
            self.waiter = Some((peer, context.vars));
            return Write::Handshake(header);
        }
        if Some(header.len()) != self.write_size || header.len() + payload.len() > MAX_HEADER {
            return Write::Drop;
        }
        self.states.insert(peer, (now + TTL, context.vars));
        header.extend_from_slice(payload);
        Write::Packet(header)
    }

    /// Returns the payload offset, or consumes a reply / drops a bad prefix.
    pub(crate) fn read(&mut self, packet: &[u8], peer: SocketAddr, now: Instant) -> Option<usize> {
        self.expire(now);
        if self.config.standalone {
            if let Some((waiting_peer, vars)) = &self.waiter {
                if *waiting_peer == peer && packet.len() == self.read_size {
                    if let Some(vars) = self.matches(packet, vars) {
                        self.states.insert(peer, (now + TTL, vars));
                        self.waiter = None;
                        return None;
                    }
                }
            }
            return Some(0);
        }
        let vars = self
            .states
            .get(&peer)
            .map(|(_, vars)| vars)
            .cloned()
            .unwrap_or_default();
        let vars = self.matches(packet, &vars)?;
        self.last_received = vars.clone();
        self.states.insert(peer, (now + TTL, vars));
        Some(self.read_size)
    }

    fn matches(&self, packet: &[u8], vars: &Vars) -> Option<Vars> {
        if packet.len() < self.read_size {
            return None;
        }
        // Xray supplies addresses to writes only, never to matching.
        let mut context = Context {
            vars: vars.clone(),
            ..Context::default()
        };
        let mut offset = 0usize;
        for item in &self.config.server {
            let length = measure_item(item, &mut context.sizes()).ok()?;
            let end = offset.checked_add(length)?;
            if !match_item(item, packet.get(offset..end)?, &mut context).ok()? {
                return None;
            }
            offset = end;
        }
        Some(context.vars)
    }
}
