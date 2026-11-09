//! The WireGuard client's userspace TCP/IP interface without WireGuard, for
//! tunnels that carry IP packets themselves, such as MASQUE's CONNECT-IP.
use crate::client::{
    Error, Flows, Routes, Stop, TcpStream, UdpSession, COMMAND_QUEUE, IP_PACKET_QUEUE, TCP_LIMIT,
    UDP_LIMIT,
};
use crate::stack;
use bytes::Bytes;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{atomic::AtomicU64, Arc},
};
use tokio::sync::{mpsc, watch, Notify, Semaphore};

/// The packet side of a [`Netstack`]: what it sends and what it receives.
#[derive(Debug)]
pub struct NetstackPackets {
    /// IP packets the stack sends, at most its MTU each.
    pub outgoing: mpsc::Receiver<Bytes>,
    /// IP packets for the stack. A full queue is backpressure; dropping it
    /// stops the stack.
    pub incoming: mpsc::Sender<Bytes>,
}

struct Owner {
    flows: Flows,
    finished: watch::Receiver<bool>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.flows.stop.close();
    }
}

/// A userspace TCP/IP interface over raw IP packets, with the bounds of the
/// WireGuard client's: 16 TCP and 512 UDP flows, and the same buffers.
#[derive(Clone)]
pub struct Netstack(Arc<Owner>);
impl fmt::Debug for Netstack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Netstack")
            .field("addresses", &self.0.flows.addresses)
            .field("closed", &self.0.flows.stop.is_closed())
            .finish_non_exhaustive()
    }
}
impl Netstack {
    /// Starts a stack with up to one local address per family. Flows may go
    /// to any usable address of a family it has an address of.
    pub fn start(addresses: Vec<IpAddr>, mtu: u16) -> Result<(Self, NetstackPackets), Error> {
        if addresses.is_empty()
            || addresses.iter().filter(|ip| ip.is_ipv4()).count() > 1
            || addresses.iter().filter(|ip| ip.is_ipv6()).count() > 1
            || addresses.iter().any(|ip| !crate::config::usable_ip(*ip))
            || !(1280..=9000).contains(&mtu)
        {
            return Err(Error::Configuration);
        }
        let stop = Stop::new();
        let wake = Arc::new(Notify::new());
        let (outgoing_tx, outgoing) = mpsc::channel(IP_PACKET_QUEUE);
        let (incoming, incoming_rx) = mpsc::channel(IP_PACKET_QUEUE);
        let (commands, requests) = mpsc::channel(COMMAND_QUEUE);
        let stack = stack::Stack::<Bytes>::new(
            &addresses,
            mtu,
            outgoing_tx,
            incoming_rx,
            requests,
            wake.clone(),
        );
        let (finished, done) = watch::channel(false);
        let task_stop = stop.clone();
        tokio::spawn(async move {
            stack.run(task_stop.clone()).await;
            task_stop.close();
            finished.send_replace(true);
        });
        Ok((
            Self(Arc::new(Owner {
                flows: Flows {
                    addresses,
                    mtu,
                    routes: Routes::Everywhere,
                    commands,
                    stop,
                    wake,
                    tcp: Arc::new(Semaphore::new(TCP_LIMIT)),
                    udp: Arc::new(Semaphore::new(UDP_LIMIT)),
                    next: AtomicU64::new(1),
                },
                finished: done,
            })),
            NetstackPackets { outgoing, incoming },
        ))
    }
    pub fn addresses(&self) -> &[IpAddr] {
        &self.0.flows.addresses
    }
    pub fn is_live(&self) -> bool {
        self.0.flows.is_live()
    }
    /// Stops the stack: open flows fail, new ones are refused.
    pub fn close(&self) {
        self.0.flows.stop.close();
    }
    pub async fn shutdown(&self) {
        self.close();
        let mut done = self.0.finished.clone();
        if !*done.borrow() {
            let _ = done.changed().await;
        }
    }
    pub fn available_tcp_slots(&self) -> usize {
        self.0.flows.tcp.available_permits()
    }
    pub fn available_udp_slots(&self) -> usize {
        self.0.flows.udp.available_permits()
    }
    pub async fn connect(&self, remote: SocketAddr) -> Result<TcpStream, Error> {
        self.0.flows.connect(remote).await
    }
    pub async fn open_udp(&self, remote: SocketAddr) -> Result<UdpSession, Error> {
        self.0.flows.open_udp(remote).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
        UdpPacket, UdpRepr,
    };
    use std::time::Duration;

    fn udp_v4(src: (Ipv4Address, u16), dst: (Ipv4Address, u16), payload: &[u8]) -> Bytes {
        let udp = UdpRepr {
            src_port: src.1,
            dst_port: dst.1,
        };
        let ip = Ipv4Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut bytes = bytes::BytesMut::zeroed(ip.buffer_len() + udp.header_len() + payload.len());
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.emit(&mut packet, &ChecksumCapabilities::default());
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &src.0.into(),
            &dst.0.into(),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        bytes.freeze()
    }

    #[tokio::test]
    async fn udp_flows_cross_the_packet_channels_in_both_families() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let local4: IpAddr = "10.66.0.2".parse().unwrap();
            let local6: IpAddr = "fd00::2".parse().unwrap();
            let (stack, mut packets) = Netstack::start(vec![local4, local6], 1280).unwrap();
            let remote: SocketAddr = "192.0.2.10:5353".parse().unwrap();
            let session = stack.open_udp(remote).await.unwrap();
            assert_eq!(session.max_payload(), 1280 - 28);
            session.send(b"ping").await.unwrap();
            let sent = packets.outgoing.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(&sent[..]).unwrap();
            assert_eq!(IpAddr::from(ip.src_addr()), local4);
            assert_eq!(IpAddr::from(ip.dst_addr()), remote.ip());
            let udp = UdpPacket::new_checked(ip.payload()).unwrap();
            assert_eq!(udp.payload(), b"ping");
            let reply = udp_v4(
                (Ipv4Address::new(192, 0, 2, 10), 5353),
                (Ipv4Address::new(10, 66, 0, 2), udp.src_port()),
                b"pong",
            );
            packets.incoming.send(reply).await.unwrap();
            assert_eq!(&session.recv().await.unwrap()[..], b"pong");

            let remote6: SocketAddr = "[2001:db8::10]:53".parse().unwrap();
            let session6 = stack.open_udp(remote6).await.unwrap();
            session6.send(b"six").await.unwrap();
            let sent = packets.outgoing.recv().await.unwrap();
            let ip = Ipv6Packet::new_checked(&sent[..]).unwrap();
            assert_eq!(IpAddr::from(ip.src_addr()), local6);
            let _ = (Ipv6Address::UNSPECIFIED, Ipv6Repr::buffer_len);
            stack.shutdown().await;
            assert!(matches!(stack.open_udp(remote).await, Err(Error::Closed)));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn only_families_with_a_local_address_are_reachable() {
        let (stack, _packets) = Netstack::start(vec!["10.66.0.2".parse().unwrap()], 1280).unwrap();
        assert!(matches!(
            stack.open_udp("[2001:db8::1]:53".parse().unwrap()).await,
            Err(Error::NoRoute)
        ));
        assert!(matches!(
            stack.open_udp("224.0.0.1:53".parse().unwrap()).await,
            Err(Error::NoRoute)
        ));
        assert!(Netstack::start(Vec::new(), 1280).is_err());
        assert!(Netstack::start(vec!["10.0.0.1".parse().unwrap()], 576).is_err());
    }
}
