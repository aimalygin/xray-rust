//! A smaller quinn receive buffer for endpoints that carry one connection.
//!
//! Quinn sizes every endpoint's receive buffer for a batch of datagrams: 32 on
//! Linux and Android, where each datagram slot also holds 64 GRO segments of
//! 1,472 bytes. A socket wrapped here asks the vendored quinn for a smaller
//! batch; GRO and everything else pass through unchanged.
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// Wraps `inner` so its endpoint reads at most `batch` datagrams per call
/// and sizes its receive buffer for that many.
pub(crate) fn cap(inner: Arc<dyn AsyncUdpSocket>, batch: usize) -> Arc<dyn AsyncUdpSocket> {
    Arc::new(ReceiveBatchCap { inner, batch })
}

#[derive(Debug)]
struct ReceiveBatchCap {
    inner: Arc<dyn AsyncUdpSocket>,
    batch: usize,
}

impl AsyncUdpSocket for ReceiveBatchCap {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn max_receive_batch(&self) -> usize {
        self.batch.min(self.inner.max_receive_batch())
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Records the receive buffers an endpoint offers, as a GRO socket would
    /// see them, and never yields a datagram.
    #[derive(Debug, Default)]
    struct RecordingSocket {
        offered: Mutex<Option<Vec<usize>>>,
    }

    impl AsyncUdpSocket for RecordingSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unreachable!("the endpoint never sends")
        }

        fn try_send(&self, _transmit: &udp::Transmit) -> io::Result<()> {
            unreachable!("the endpoint never sends")
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            assert_eq!(bufs.len(), meta.len());
            *self.offered.lock().unwrap() = Some(bufs.iter().map(|buf| buf.len()).collect());
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 9)))
        }

        fn max_receive_segments(&self) -> usize {
            64
        }
    }

    /// The receive buffers an endpoint on `socket` offers `recorder` first.
    async fn offered_buffers(
        socket: Arc<dyn AsyncUdpSocket>,
        recorder: &RecordingSocket,
    ) -> Vec<usize> {
        let _endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(offered) = recorder.offered.lock().unwrap().take() {
                    return offered;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the endpoint driver polls its socket")
    }

    #[tokio::test]
    async fn a_capped_endpoint_offers_only_its_batch_of_gro_slots() {
        let slot = 1_472 * 64;
        let recorder = Arc::new(RecordingSocket::default());
        let offered = offered_buffers(cap(recorder.clone(), 4), &recorder).await;
        assert_eq!(offered, vec![slot; 4.min(udp::BATCH_SIZE)]);

        let recorder = Arc::new(RecordingSocket::default());
        let offered = offered_buffers(recorder.clone(), &recorder).await;
        assert_eq!(
            offered,
            vec![slot; udp::BATCH_SIZE],
            "an uncapped socket keeps quinn's batch"
        );

        let recorder = Arc::new(RecordingSocket::default());
        let offered = offered_buffers(cap(recorder.clone(), 1_000), &recorder).await;
        assert_eq!(
            offered,
            vec![slot; udp::BATCH_SIZE],
            "a cap never raises quinn's batch"
        );
    }
}
