//! Controlled authenticated peers: expose inner packets so tests can forge a
//! valid UDP reply under the wrong peer's key, without replacing client code.
use bytes::BytesMut;
use gotatun::{
    device::{DeviceBuilder, DeviceLimits, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, UdpPacket};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_proxy::wireguard::KeyMaterial;
use xray_wireguard::PeerConfig;

pub struct RawPeer {
    pub config: PeerConfig,
    pub received: mpsc::Receiver<Packet<Ip>>,
    pub inject: mpsc::Sender<Packet<Ip>>,
    stop: Option<oneshot::Sender<()>>,
    done: Option<JoinHandle<()>>,
}
impl Drop for RawPeer {
    fn drop(&mut self) {
        self.stop.take();
    }
}
impl RawPeer {
    pub async fn start(seed: u8, ipv6: bool, prefixes: &[&str]) -> Self {
        let socket = Arc::new(
            UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap(),
        );
        let secret = StaticSecret::from([seed; 32]);
        let psk = [seed + 1; 32];
        let config = PeerConfig {
            public_key: key(PublicKey::from(&secret).as_bytes()),
            preshared_key: Some(key(&psk)),
            endpoint: socket.local_addr().unwrap(),
            allowed_ips: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            keepalive: 0,
        };
        let mut peer = Peer::new(PublicKey::from(&StaticSecret::from([0x42; 32])))
            .with_allowed_ips([
                "10.44.0.2/32".parse().unwrap(),
                "fd44::2/128".parse().unwrap(),
            ]);
        peer.preshared_key = Some(gotatun::PresharedKey::new(&psk));
        let (tx, received) = mpsc::channel(8);
        let (inject, rx) = mpsc::channel(8);
        let mut device = DeviceBuilder::new()
            .with_limits(DeviceLimits::mobile())
            .with_private_key(secret)
            .with_peer(peer)
            .with_udp(Udp(socket))
            .with_ip_pair(IpTx(tx), IpRx(rx))
            .build()
            .await
            .unwrap();
        let (stop, stopped) = oneshot::channel();
        let done = tokio::spawn(async move {
            tokio::select! { _ = stopped => {}, _ = device.wait() => panic!("raw peer failed") }
            device.stop().await;
        });
        Self {
            config,
            received,
            inject,
            stop: Some(stop),
            done: Some(done),
        }
    }
    pub async fn shutdown(&mut self) {
        self.stop.take();
        self.done.take().unwrap().await.unwrap();
    }
}
pub fn key(bytes: &[u8; 32]) -> KeyMaterial {
    KeyMaterial::parse(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap()
}
#[derive(Clone)]
struct Udp(Arc<UdpSocket>);
impl UdpTransportFactory for Udp {
    type Send = Self;
    type Recv = Self;
    async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(Self, Self)> {
        Ok((self.clone(), self.clone()))
    }
}
impl UdpSend for Udp {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        assert_eq!(self.0.send_to(&packet, destination).await?, packet.len());
        Ok(())
    }
}
impl UdpRecv for Udp {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut packet = pool.get();
        let (n, source) = self.0.recv_from(&mut packet).await?;
        packet.truncate(n);
        Ok((packet, source))
    }
}
struct IpTx(mpsc::Sender<Packet<Ip>>);
struct IpRx(mpsc::Receiver<Packet<Ip>>);
impl IpSend for IpTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.0
            .send(packet)
            .await
            .map_err(|_| io::Error::other("sink closed"))
    }
}
impl IpRecv for IpRx {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        Ok(std::iter::once(
            self.0
                .recv()
                .await
                .ok_or_else(|| io::Error::other("source closed"))?,
        ))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}
// Preserve the exact flow tuple and valid IP/UDP checksums. A mere mismatched
// port/source test could pass because of smoltcp's flow filtering, hiding a
// missing WireGuard authenticated-source check.
pub fn reply(request: &Packet, payload: &[u8]) -> Packet<Ip> {
    let mut bytes = BytesMut::from(&request[..]);
    let (source, destination, offset) = if bytes[0] >> 4 == 4 {
        let mut ip = Ipv4Packet::new_checked(&mut bytes[..]).unwrap();
        let (source, destination) = (ip.dst_addr(), ip.src_addr());
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        ip.fill_checksum();
        (source.into(), destination.into(), 20)
    } else {
        let mut ip = Ipv6Packet::new_checked(&mut bytes[..]).unwrap();
        let (source, destination) = (ip.dst_addr(), ip.src_addr());
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        (source.into(), destination.into(), 40)
    };
    let mut udp = UdpPacket::new_checked(&mut bytes[offset..]).unwrap();
    let port = udp.src_port();
    udp.set_src_port(udp.dst_port());
    udp.set_dst_port(port);
    assert_eq!(udp.payload_mut().len(), payload.len());
    udp.payload_mut().copy_from_slice(payload);
    udp.fill_checksum(&source, &destination);
    Packet::from_bytes(bytes).try_into_ip().unwrap()
}
