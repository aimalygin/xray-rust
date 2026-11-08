//! Xray-core's `xdnsClient`: each packet goes out in the names of queries
//! to the resolvers, and polls keep queries waiting at the server for what
//! it sends back.
use super::{
    domain::{type_bits, Domain},
    message::{self, Read},
    resolver::{self, Resolver},
    XdnsConfig, XdnsError,
};
use crate::SocketProtector;
use rand::{Rng, RngCore};
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle, time::Instant};

/// How long the client waits to poll after an answer, doubling while none
/// comes, up to `MAX_POLL_DELAY`.
const INIT_POLL_DELAY: Duration = Duration::from_millis(500);
const MAX_POLL_DELAY: Duration = Duration::from_secs(10);
/// Answers that each ask for a poll, as many as Xray's channel holds.
const POLL_LIMIT: usize = 16;
/// The largest packet Xray's client takes.
pub(crate) const MAX_PACKET: usize = 4096;
/// Packets read and not yet taken. Xray hands each over unbuffered, so a
/// resolver's reader waits; here it waits once this many are queued.
const RECEIVE_QUEUE: usize = 64;

/// A packet the client read and the resolver it came through.
#[derive(Debug)]
pub(crate) struct Packet {
    pub(crate) data: Vec<u8>,
    pub(crate) from: SocketAddr,
}

/// One client: an id for the server to know it by and the resolvers it
/// queries. Dropping it stops its tasks and closes its resolvers.
pub struct XdnsClient {
    shared: Arc<Shared>,
    received: Mutex<mpsc::Receiver<Packet>>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for XdnsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdnsClient")
            .field("resolvers", &self.shared.resolvers.len())
            .finish_non_exhaustive()
    }
}

struct Shared {
    client_id: [u8; 8],
    fragment_id: AtomicU32,
    domains: Vec<Domain>,
    extra_poll: u8,
    resolvers: Vec<Box<dyn Resolver>>,
    resolver_sends: Vec<AtomicU32>,
    resolver_index: AtomicU32,
}

impl XdnsClient {
    /// Opens every resolver, as `NewClient` does: one that does not open
    /// fails the client.
    pub async fn connect(
        config: &XdnsConfig,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Self, XdnsError> {
        let domains = config.domains()?;
        if config.resolvers.is_empty() {
            return Err(XdnsError::Config("xdns needs a resolver"));
        }
        if config.extra_poll > 3 {
            return Err(XdnsError::Config("extraPoll must be 0 to 3"));
        }
        let (received_tx, received) = mpsc::channel(RECEIVE_QUEUE);
        let (poll_tx, poll_rx) = mpsc::channel(POLL_LIMIT);
        let mut resolvers = Vec::with_capacity(config.resolvers.len());
        let mut responses = Vec::with_capacity(config.resolvers.len());
        for endpoint in &config.resolvers {
            let (resolver, rx) = resolver::open(endpoint, protector.clone()).await?;
            resolvers.push(resolver);
            responses.push(rx);
        }
        let shared = Arc::new(Shared {
            client_id: client_id(),
            fragment_id: AtomicU32::new(0),
            domains,
            extra_poll: config.extra_poll,
            resolver_sends: resolvers.iter().map(|_| AtomicU32::new(0)).collect(),
            resolvers,
            resolver_index: AtomicU32::new(0),
        });
        let mut tasks = Vec::with_capacity(responses.len() + 1);
        for (index, rx) in responses.into_iter().enumerate() {
            tasks.push(tokio::spawn(receive(
                shared.clone(),
                index,
                rx,
                received_tx.clone(),
                poll_tx.clone(),
            )));
        }
        tasks.push(tokio::spawn(poll(shared.clone(), poll_rx)));
        Ok(Self {
            shared,
            received: Mutex::new(received),
            tasks,
        })
    }

    /// `WriteTo`: the packet, then `extraPoll` polls. A packet that is
    /// empty or over 4096 bytes is refused.
    pub(crate) fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > MAX_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xdns sends packets of 1 to 4096 bytes",
            ));
        }
        self.shared.send(packet);
        for _ in 0..self.shared.extra_poll {
            self.shared.send(&[]);
        }
        Ok(())
    }

    /// The next packet read, `None` once every resolver's reader stopped.
    pub(crate) fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<Packet>> {
        self.received
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .poll_recv(cx)
    }

    /// Another packet already read, without waiting.
    pub(crate) fn try_recv(&self) -> Option<Packet> {
        self.received
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .try_recv()
            .ok()
    }

    pub(crate) async fn recv(&self) -> Option<Packet> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}

impl Drop for XdnsClient {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for resolver in &self.shared.resolvers {
            resolver.close();
        }
    }
}

/// `NewClientID`: random, with the two bits for the query type clear.
fn client_id() -> [u8; 8] {
    let mut id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut id);
    id[0] &= 0xFC;
    id
}

impl Shared {
    /// `send`: a poll for an empty packet, one query for a packet that fits
    /// a name, fragments for a larger one, all under one domain and type.
    fn send(&self, packet: &[u8]) {
        let mut rng = rand::thread_rng();
        let domain = &self.domains[rng.gen_range(0..self.domains.len())];
        let qtype = domain.types()[rng.gen_range(0..domain.types().len())];
        let capacity = domain.capacity();
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(&self.client_id);
        data[0] |= type_bits(qtype);
        if packet.is_empty() {
            data.push(8);
            data.extend(std::iter::repeat_with(|| rng.gen::<u8>()).take(8));
            self.query(domain, qtype, &data);
            return;
        }
        if packet.len() <= capacity - 12 {
            data.push(3);
            data.extend(std::iter::repeat_with(|| rng.gen::<u8>()).take(3));
            data.extend_from_slice(packet);
            self.query(domain, qtype, &data);
            return;
        }
        let chunk = capacity - 15;
        // Xray logs a packet too large for the domain and drops it.
        if packet.len() > 255 * chunk {
            return;
        }
        data.push(3 | 0xC0);
        data.extend(std::iter::repeat_with(|| rng.gen::<u8>()).take(3));
        let fragment_id = self
            .fragment_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1) as u8;
        let count = packet.len().div_ceil(chunk);
        for (index, fragment) in packet.chunks(chunk).enumerate() {
            data.truncate(12);
            data.extend_from_slice(&[fragment_id, index as u8, count as u8]);
            data.extend_from_slice(fragment);
            self.query(domain, qtype, &data);
        }
    }

    /// One query, with a random id, through the resolver Xray's balance
    /// picks: the current one, then the next that has sent fewer queries
    /// since it last answered.
    fn query(&self, domain: &Domain, qtype: u16, data: &[u8]) {
        let id = rand::thread_rng().gen::<u16>();
        let query = message::query(id, &domain.encode(data), qtype, domain.edns0());
        let count = self.resolvers.len();
        let index = self.resolver_index.load(Ordering::Relaxed) as usize % count;
        let sent = self.resolver_sends[index].fetch_add(1, Ordering::Relaxed) + 1;
        let mut next = index;
        loop {
            next = (next + 1) % count;
            if next == index || sent > self.resolver_sends[next].load(Ordering::Relaxed) {
                break;
            }
        }
        self.resolver_index.store(next as u32, Ordering::Relaxed);
        self.resolvers[index].send(query);
    }
}

/// `recv`: reads one resolver's responses. One that carried packets resets
/// the resolver's count and asks for a poll.
async fn receive(
    shared: Arc<Shared>,
    index: usize,
    mut responses: mpsc::Receiver<Vec<u8>>,
    received: mpsc::Sender<Packet>,
    poll: mpsc::Sender<()>,
) {
    while let Some(response) = responses.recv().await {
        let Read::Answer { packets, .. } = message::read(&response, &shared.domains) else {
            continue;
        };
        if packets.is_empty() {
            continue;
        }
        let from = shared.resolvers[index].addr();
        for data in packets {
            if received.send(Packet { data, from }).await.is_err() {
                return;
            }
        }
        shared.resolver_sends[index].store(0, Ordering::Relaxed);
        let _ = poll.try_send(());
    }
}

/// `poll`: from the first answer on, a poll at once for each answer that
/// carried packets, and otherwise after a delay that doubles to 10 seconds.
async fn poll(shared: Arc<Shared>, mut answers: mpsc::Receiver<()>) {
    if answers.recv().await.is_none() {
        return;
    }
    let mut delay = INIT_POLL_DELAY;
    let mut deadline = Instant::now() + delay;
    loop {
        tokio::select! {
            answer = answers.recv() => {
                if answer.is_none() {
                    return;
                }
                delay = INIT_POLL_DELAY;
            }
            () = tokio::time::sleep_until(deadline) => {
                delay = (delay * 2).min(MAX_POLL_DELAY);
            }
        }
        deadline = Instant::now() + delay;
        shared.send(&[]);
        for _ in 0..shared.extra_poll {
            shared.send(&[]);
        }
    }
}

#[cfg(test)]
mod tests;
