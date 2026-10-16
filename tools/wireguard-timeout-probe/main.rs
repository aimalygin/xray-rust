//! Same injected IP/UDP boundary for pristine and patched GotaTun.
//! Fixed synthetic keys, loopback only, no host TUN or routes.
use bytes::BytesMut;
use gotatun::{
    device::{DeviceBuilder, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    x25519::{PublicKey, StaticSecret},
};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::{UdpSocket, UnixDatagram};

#[derive(Clone)]
struct Wire(Arc<UdpSocket>);
impl UdpTransportFactory for Wire {
    type Send = Self;
    type Recv = Self;
    async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(Self, Self)> {
        Ok((self.clone(), self.clone()))
    }
}
impl UdpSend for Wire {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        assert!(destination.ip().is_loopback());
        assert_eq!(self.0.send_to(&packet, destination).await?, packet.len());
        Ok(())
    }
}
impl UdpRecv for Wire {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut packet = pool.get();
        let (n, source) = self.0.recv_from(&mut packet).await?;
        packet.truncate(n);
        Ok((packet, source))
    }
}
struct Inner(Arc<UnixDatagram>);
impl IpSend for Inner {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        assert_eq!(self.0.send(&bytes).await?, bytes.len());
        Ok(())
    }
}
impl IpRecv for Inner {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut buf = [0; 1421];
        let n = self.0.recv(&mut buf).await?;
        assert!(n <= 1420);
        let packet = Packet::from_bytes(BytesMut::from(&buf[..n]))
            .try_into_ip()
            .map_err(|_| io::Error::other("invalid test packet"))?;
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: timeout-probe ENDPOINT LOCAL_SOCKET REMOTE_SOCKET"
    );
    let endpoint: SocketAddr = args[1].parse().unwrap();
    assert!(endpoint.ip().is_loopback() && endpoint.port() != 0);
    let inner = Arc::new(UnixDatagram::bind(&args[2]).unwrap());
    inner.connect(&args[3]).unwrap();
    let socket = Arc::new(UdpSocket::bind((endpoint.ip(), 0)).await.unwrap());
    let peer = Peer::new(PublicKey::from(&StaticSecret::from([0x53; 32])))
        .with_endpoint(endpoint)
        .with_allowed_ips(["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]);
    let builder = DeviceBuilder::new();
    #[cfg(feature = "xray-patches")]
    let builder = builder.with_limits({
        let mut limits = gotatun::device::DeviceLimits::mobile();
        limits.packet_reservations = 256;
        limits.io_queue_packets = 16;
        limits.pending_packets_per_peer = limits.pending_packets;
        limits
    });
    let mut device = builder
        .with_private_key(StaticSecret::from([0x42; 32]))
        .with_peer(peer)
        .with_udp(Wire(socket))
        .with_ip_pair(Inner(inner.clone()), Inner(inner))
        .build()
        .await
        .unwrap();
    println!("raw gotatun ready");
    device.wait().await;
    panic!("raw engine stopped unexpectedly");
}
