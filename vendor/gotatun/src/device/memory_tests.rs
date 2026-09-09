// SPDX-License-Identifier: MPL-2.0
//! No sockets, system TUN or remote traffic: exercise real device workers with bounded adapters.
use super::{Device, DeviceBuilder, DeviceLimits, DeviceState, Error, Peer};
use crate::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    future::pending,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc},
    time::{sleep, timeout},
};

#[derive(Default)]
struct State {
    binds: AtomicUsize,
    consumed: AtomicUsize,
    writes: AtomicUsize,
    blocked: AtomicBool,
    wake: Notify,
}
struct Factory(Arc<State>);
#[derive(Clone)]
struct Udp(Arc<State>);
impl UdpTransportFactory for Factory {
    type Send = Udp;
    type Recv = Udp;
    async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(Udp, Udp)> {
        self.0.binds.fetch_add(1, Ordering::SeqCst);
        Ok((Udp(self.0.clone()), Udp(self.0.clone())))
    }
}
impl UdpSend for Udp {
    type SendManyBuf = ();
    async fn send_to(&self, _packet: Packet, _: SocketAddr) -> io::Result<()> {
        while self.0.blocked.load(Ordering::SeqCst) {
            self.0.wake.notified().await;
        }
        self.0.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    // A maliciously large batching hint must not preallocate this much storage.
    fn max_number_of_packets_to_send(&self) -> usize {
        usize::MAX
    }
}
impl UdpRecv for Udp {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, _: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        pending().await
    }
    async fn recv_many_from(
        &mut self,
        _: &mut (),
        _: &mut PacketBufPool,
        _: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        panic!("bounded device must receive single packets")
    }
}
struct IpTx;
struct IpRx(mpsc::Receiver<Packet<Ip>>, Arc<State>);
impl IpSend for IpTx {
    async fn send(&mut self, _: Packet<Ip>) -> io::Result<()> {
        Ok(())
    }
}
impl IpRecv for IpRx {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let packet = self
            .0
            .recv()
            .await
            .ok_or_else(|| io::Error::other("closed"))?;
        self.1.consumed.fetch_add(1, Ordering::SeqCst);
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}
type TestDevice = Device<(Factory, IpTx, IpRx)>;
fn builder(state: Arc<State>) -> (DeviceBuilder<Factory, IpTx, IpRx>, mpsc::Sender<Packet<Ip>>) {
    let (tx, rx) = mpsc::channel(8);
    let builder = DeviceBuilder::new()
        .with_udp(Factory(state.clone()))
        .with_ip_pair(IpTx, IpRx(rx, state))
        .with_private_key(StaticSecret::from([0x42; 32]))
        .with_peer(
            Peer::new(PublicKey::from(&StaticSecret::from([0x53; 32])))
                .with_endpoint((Ipv4Addr::LOCALHOST, 51820).into())
                .with_allowed_ip("0.0.0.0/0".parse().unwrap()),
        )
        .with_limits(DeviceLimits::mobile());
    (builder, tx)
}
async fn drained(device: &TestDevice) {
    timeout(Duration::from_secs(3), async {
        loop {
            if device.memory_snapshot().await.unwrap().reservations == 0 {
                break;
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("all engine reservations must be released");
}

#[tokio::test]
async fn unreachable_peer_flood_and_repeated_suspend_release_memory() {
    timeout(Duration::from_secs(20), async {
        let state = Arc::new(State::default());
        let (builder, tx) = builder(state.clone());
        let device = builder.build().await.unwrap();
        let mut accepted = 0;
        for generation in 0..5 {
            for _ in 0..10_000 {
                tx.send(super::tests::mock::packet([0; 1400]))
                    .await
                    .unwrap();
                accepted += 1;
            }
            while state.consumed.load(Ordering::SeqCst) < accepted {
                tokio::task::yield_now().await;
            }
            // Wait until the final input has passed the worker into the peer queue.
            timeout(Duration::from_secs(3), async {
                loop {
                    let stats = device.memory_snapshot().await.unwrap();
                    if stats.pending_packets == 8 && stats.reservations == 8 {
                        break;
                    }
                    sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            let stats = device.memory_snapshot().await.unwrap();
            assert!(stats.peak_reservations <= 64);
            assert_eq!(stats.peak_pending_packets, 8);
            assert!(stats.pending_drops >= (generation + 1) * (10_000 - 8));
            device.suspend().await;
            drained(&device).await;
            assert!(device.inner.read().await.peers_by_idx.lock().is_empty());
            device.resume().await.unwrap();
            assert_eq!(state.binds.load(Ordering::SeqCst), generation as usize + 2);
        }
        assert!(matches!(
            device
                .write(async |_| panic!("immutable callback must not execute"))
                .await,
            Err(Error::BoundedConfigurationImmutable)
        ));
        // Stop with another state owner retained, as a core diagnostic handle might do.
        let inner = device.inner.clone();
        Device::stop_inner(inner.clone()).await;
        drained(&device).await;
        device.stop().await;
        assert_eq!(
            inner
                .read()
                .await
                .memory
                .as_ref()
                .unwrap()
                .snapshot()
                .reservations,
            0
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn blocked_udp_queue_cancellation_releases_every_lease() {
    let memory = super::memory::MemoryBudget::new(DeviceLimits::mobile());
    let state = Arc::new(State::default());
    state.blocked.store(true, Ordering::SeqCst);
    let udp = crate::udp::buffer::BufferedUdpSend::with_memory(
        16,
        Udp(state.clone()),
        Some(memory.clone()),
    );
    let sender = tokio::spawn(async move {
        for _ in 0..10_000 {
            udp.send_to(
                Packet::copy_from(&[0; 1420][..]),
                (Ipv4Addr::LOCALHOST, 1).into(),
            )
            .await
            .unwrap();
        }
    });
    sleep(Duration::from_millis(30)).await;
    let stats = memory.snapshot();
    assert!(
        stats.reservations >= 17 && stats.reservations <= 34,
        "{stats:?}"
    );
    assert_eq!(state.writes.load(Ordering::SeqCst), 0);
    sender.abort();
    assert!(sender.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(3), async {
        while memory.snapshot().reservations != 0 {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_limits_and_peer_count_fail_before_bind() {
    for case in 0..5 {
        let state = Arc::new(State::default());
        let (mut builder, _tx) = builder(state.clone());
        let mut limits = DeviceLimits::mobile();
        match case {
            0 => limits.io_queue_packets = 0,
            1 => limits.packet_reservations = 0,
            2 => limits.max_ip_packet_size = usize::MAX,
            3 => limits.pending_packets = 64,
            _ => {
                limits.max_peers = 1;
                builder =
                    builder.with_peer(Peer::new(PublicKey::from(&StaticSecret::from([0x64; 32]))));
            }
        }
        assert!(matches!(
            builder.with_limits(limits).build().await,
            Err(Error::InvalidMemoryLimits)
        ));
        assert_eq!(state.binds.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn handshake_index_map_prunes_expired_entries_without_waiting_for_timer() {
    let (builder, _tx) = builder(Arc::new(State::default()));
    let device = builder.suspended(true).build().await.unwrap();
    let state = device.inner.read().await;
    let peer = state.peers.values().next().unwrap();
    let mut peer_state = peer.lock().await;
    for _ in 0..10_000 {
        let packet = peer_state
            .tunnel
            .format_handshake_initiation(true)
            .unwrap()
            .into();
        DeviceState::<(Factory, IpTx, IpRx)>::register_handshake_idx(
            &state.index_table,
            &state.peers_by_idx,
            &packet,
            peer,
        );
        // Noise retains both the current and previous handshake.
        assert!(state.peers_by_idx.lock().len() <= 2);
    }
    drop(peer_state);
    drop(state);
    device.stop().await;
}
