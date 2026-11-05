//! A UDP flow's datagram channel, with the datagrams that sniffing read
//! ahead put back in front.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch};
use xray_config::InboundSniffingConfig;
use xray_routing::Target;

use crate::sniffing::{Sniffed, UdpSniffProgress, UdpSniffer, QUIC_MAX_CRYPTO_STREAM_SIZE};

/// Xray-core waits at most 200 ms in total for the rest of a ClientHello.
const SNIFF_WAIT: Duration = Duration::from_millis(200);

/// The datagrams of one UDP flow after its first.
#[derive(Debug)]
pub(crate) struct UdpIngress {
    replay: VecDeque<Bytes>,
    rx: mpsc::Receiver<Bytes>,
}

impl From<mpsc::Receiver<Bytes>> for UdpIngress {
    fn from(rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            replay: VecDeque::new(),
            rx,
        }
    }
}

impl UdpIngress {
    /// Cancel-safe like [`mpsc::Receiver::recv`]: a replayed datagram is taken
    /// only when the future completes.
    pub(crate) async fn recv(&mut self) -> Option<Bytes> {
        match self.replay.pop_front() {
            Some(datagram) => Some(datagram),
            None => self.rx.recv().await,
        }
    }
}

/// Sniffs a UDP flow from its first datagram, reading later ones while a QUIC
/// ClientHello continues across datagrams.
///
/// Like Xray-core, it waits at most [`SNIFF_WAIT`] in total and buffers at
/// most as many bytes as a reassembled ClientHello may hold. Shutdown, a
/// closed channel or either limit ends the wait with nothing named. Every
/// datagram read here is replayed, in order, by the returned ingress.
pub(crate) async fn sniff_udp_flow(
    config: &InboundSniffingConfig,
    original: &Target,
    first: &[u8],
    rx: mpsc::Receiver<Bytes>,
    shutdown: &mut watch::Receiver<bool>,
) -> (Option<Sniffed>, UdpIngress) {
    let mut ingress = UdpIngress::from(rx);
    let mut sniffer = UdpSniffer::new(config, original);
    let deadline = tokio::time::Instant::now() + SNIFF_WAIT;
    let mut buffered = first.len();
    let mut progress = sniffer.feed(first);
    while matches!(progress, UdpSniffProgress::NeedMore) && buffered < QUIC_MAX_CRYPTO_STREAM_SIZE {
        let next = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            next = tokio::time::timeout_at(deadline, ingress.rx.recv()) => next,
        };
        let Ok(Some(datagram)) = next else {
            break;
        };
        buffered += datagram.len();
        progress = sniffer.feed(&datagram);
        ingress.replay.push_back(datagram);
    }
    let sniffed = match progress {
        UdpSniffProgress::Done(sniffed) => sniffed,
        UdpSniffProgress::NeedMore => None,
    };
    (sniffed, ingress)
}

#[cfg(test)]
mod tests {
    use xray_config::SniffingDestination;
    use xray_routing::{Network, TargetAddr};

    use super::*;

    fn config() -> InboundSniffingConfig {
        InboundSniffingConfig {
            enabled: true,
            dest_override: vec![SniffingDestination::Quic],
            metadata_only: false,
            route_only: true,
            ..Default::default()
        }
    }

    fn original() -> Target {
        Target::new(
            TargetAddr::Ip("127.0.0.1".parse().unwrap()),
            443,
            Network::Udp,
        )
    }

    /// One ClientHello for `chrome-parrot.example` in two datagrams.
    fn split_client_hello() -> [Bytes; 2] {
        let mut datagrams =
            include_str!("../../../tests/fixtures/quic/xray-chrome-parrot-client-initials.hex")
                .lines()
                .map(|line| {
                    (0..line.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
                        .collect::<Bytes>()
                });
        [datagrams.next().unwrap(), datagrams.next().unwrap()]
    }

    fn sniffed_domain(sniffed: Option<Sniffed>) -> Option<String> {
        sniffed
            .and_then(|sniffed| sniffed.target)
            .map(|sniffed| match sniffed.route_target.addr {
                TargetAddr::Domain(domain) => domain,
                other => panic!("sniffing produced a non-domain target {other:?}"),
            })
    }

    #[tokio::test(start_paused = true)]
    async fn reads_ahead_until_the_client_hello_completes_and_replays_in_order() {
        let [first, second] = split_client_hello();
        let (tx, rx) = mpsc::channel(4);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        tx.send(second.clone()).await.unwrap();
        tx.send(Bytes::from_static(b"later")).await.unwrap();

        let started = tokio::time::Instant::now();
        let (sniffed, mut ingress) =
            sniff_udp_flow(&config(), &original(), &first, rx, &mut shutdown).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(
            sniffed_domain(sniffed).as_deref(),
            Some("chrome-parrot.example")
        );
        // The datagram read for sniffing comes back first; nothing more was read.
        assert_eq!(ingress.recv().await, Some(second));
        assert_eq!(ingress.recv().await, Some(Bytes::from_static(b"later")));
        drop(tx);
        assert_eq!(ingress.recv().await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_the_wait_shutdown_or_a_closed_channel() {
        let [first, second] = split_client_hello();

        let (tx, rx) = mpsc::channel(4);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let (sniffed, mut ingress) =
            sniff_udp_flow(&config(), &original(), &first, rx, &mut shutdown).await;
        assert_eq!(started.elapsed(), SNIFF_WAIT);
        assert!(sniffed.is_none());
        // A datagram that arrives after the wait is still delivered.
        tx.send(second.clone()).await.unwrap();
        assert_eq!(ingress.recv().await, Some(second));

        let (_tx, rx) = mpsc::channel(4);
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let (sniffing, target) = (config(), original());
        let started = tokio::time::Instant::now();
        let (sniffed, _) = tokio::join!(
            sniff_udp_flow(&sniffing, &target, &first, rx, &mut shutdown),
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                shutdown_tx.send_replace(true);
            },
        )
        .0;
        assert_eq!(started.elapsed(), Duration::from_millis(20));
        assert!(sniffed.is_none());

        let (tx, rx) = mpsc::channel::<Bytes>(4);
        drop(tx);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let (sniffed, _) = sniff_udp_flow(&config(), &original(), &first, rx, &mut shutdown).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(sniffed.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_wait_or_read_ahead_for_other_traffic() {
        let (tx, rx) = mpsc::channel(4);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        tx.send(Bytes::from_static(b"second")).await.unwrap();
        let started = tokio::time::Instant::now();
        let (sniffed, mut ingress) =
            sniff_udp_flow(&config(), &original(), b"not QUIC", rx, &mut shutdown).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(sniffed.is_none());
        assert!(ingress.replay.is_empty());
        assert_eq!(ingress.recv().await, Some(Bytes::from_static(b"second")));
    }
}
