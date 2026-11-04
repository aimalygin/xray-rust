//! Freedom's `finalRules`, applied as Xray-core v26.10.31's freedom applies
//! them: the first rule that applies to an address decides, and a blocked
//! connection is held open, discarding what the client sends, until the client
//! is done or the rule's block delay passes.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use xray_config::{deciding_final_rule, FreedomFinalRule, FreedomRuleAction, Network};
use xray_routing::{Target, TargetAddr};
use xray_transport::{DnsResolver, TransportError, TransportStream};

/// Xray-core's block delay when a rule sets none, in seconds.
const DEFAULT_BLOCK_DELAY_SECS: (u32, u32) = (30, 90);

/// The rule that blocks one of `addresses`: Xray-core blocks the whole
/// connection when the rule deciding any one of them blocks.
pub(crate) fn blocking_rule(
    rules: &[FreedomFinalRule],
    network: Network,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Option<&FreedomFinalRule> {
    addresses.into_iter().find_map(|address| {
        deciding_final_rule(rules, network, address.ip(), address.port())
            .filter(|rule| rule.action == FreedomRuleAction::Block)
    })
}

/// Whether the rule deciding `address` blocks it.
pub(crate) fn blocks(rules: &[FreedomFinalRule], network: Network, address: SocketAddr) -> bool {
    blocking_rule(rules, network, [address]).is_some()
}

/// Resolves a freedom UDP destination to the address its datagrams go to.
/// With `rules`, the second value holds every address the destination has,
/// since Xray-core checks them all before it dials; otherwise it is empty.
pub(crate) async fn resolve_udp_destination(
    target: &Target,
    resolver: &dyn DnsResolver,
    rules: &[FreedomFinalRule],
) -> Result<(SocketAddr, Vec<SocketAddr>), TransportError> {
    let checked = !rules.is_empty();
    match &target.addr {
        TargetAddr::Ip(ip) => {
            let address = SocketAddr::new(*ip, target.port);
            Ok((address, if checked { vec![address] } else { Vec::new() }))
        }
        TargetAddr::Domain(domain) if checked => {
            let addresses = resolver
                .resolve_all(domain, target.port)
                .await?
                .socket_addrs()
                .to_vec();
            let first = addresses
                .first()
                .copied()
                .ok_or_else(|| TransportError::NoResolvedAddress(domain.clone(), target.port))?;
            Ok((first, addresses))
        }
        TargetAddr::Domain(domain) => {
            Ok((resolver.resolve(domain, target.port).await?, Vec::new()))
        }
    }
}

/// How long `rule` holds a blocked connection: whole seconds drawn uniformly
/// from its range.
pub(crate) fn block_delay(rule: &FreedomFinalRule) -> Duration {
    let (min, max) = rule.block_delay.map_or(DEFAULT_BLOCK_DELAY_SECS, |delay| {
        (delay.min_secs, delay.max_secs)
    });
    Duration::from_secs(rand::thread_rng().gen_range(min..=max).into())
}

/// A TCP connection a final rule blocked, standing in for the outbound
/// stream. Writes are discarded. Reads end once the client half-closes, and
/// fail when the block delay passes, which closes the whole connection as
/// Xray-core interrupts both directions then.
pub(crate) struct BlockedStream {
    delay: Pin<Box<Sleep>>,
    client_done: bool,
    reader: Option<Waker>,
}

impl BlockedStream {
    pub(crate) fn new(delay: Duration) -> Self {
        Self {
            delay: Box::pin(tokio::time::sleep_until(
                Instant::now().checked_add(delay).unwrap_or_else(far_future),
            )),
            client_done: false,
            reader: None,
        }
    }
}

/// tokio's own fallback for a deadline it cannot represent.
fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400 * 365 * 30)
}

impl AsyncRead for BlockedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.client_done {
            return Poll::Ready(Ok(()));
        }
        if self.delay.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "blocked by a freedom final rule",
            )));
        }
        self.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for BlockedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.client_done = true;
        if let Some(reader) = self.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for BlockedStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

#[cfg(test)]
mod tests;
