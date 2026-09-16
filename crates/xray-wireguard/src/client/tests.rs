use super::*;
use gotatun::packet::Packet;
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_proxy::wireguard::KeyMaterial;

// Exercise real smoltcp state transitions through the same IP/command channels
// used by the engine, without relying on a proxy server's FIN/RST translation.
#[tokio::test]
async fn tcp_reset_is_an_error_after_buffered_bytes_and_releases_flow() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = Config {
            secret_key: KeyMaterial::parse(&"42".repeat(32)).unwrap(),
            peers: vec![crate::PeerConfig {
                public_key: KeyMaterial::parse(&"53".repeat(32)).unwrap(),
                preshared_key: None,
                endpoint: "127.0.0.1:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                keepalive: 0,
            }],
            addresses: vec!["10.44.0.2".parse().unwrap()],
            mtu: 1420,
        };
        let wake = Arc::new(Notify::new());
        let (out, mut packets) = mpsc::channel(PACKET_QUEUE);
        let (incoming, input) = mpsc::channel(PACKET_QUEUE);
        let (commands, requests) = mpsc::channel(COMMAND_QUEUE);
        let stop = Stop::new();
        let stack = stack::Stack::new(&config, out, input, requests, wake.clone());
        let task = tokio::spawn(stack.run(stop.clone()));
        let slots = Arc::new(Semaphore::new(1));
        let flow = Arc::new(Flow {
            id: 1,
            closed: AtomicBool::new(false),
            reset: AtomicBool::new(false),
            wake,
        });
        let (stream, bridge) = tokio::io::duplex(STREAM_BUFFER);
        let mut stream = TcpStream {
            stream,
            _guard: FlowGuard(flow.clone()),
        };
        let (reply, ready) = oneshot::channel();
        commands
            .send(Command::Tcp {
                local: config.addresses[0],
                remote: "198.51.100.7:443".parse().unwrap(),
                bridge,
                reply,
                flow,
                permit: slots.clone().acquire_owned().await.unwrap(),
            })
            .await
            .unwrap();
        let syn = packets.recv().await.unwrap();
        let bytes = syn.into_bytes();
        let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let ack = tcp.seq_number() + 1;
        let local_port = tcp.src_port();
        incoming
            .send(reply_packet(local_port, 100, ack, true, false, &[]))
            .await
            .unwrap();
        ready.await.unwrap().unwrap();
        incoming
            .send(reply_packet(
                local_port,
                101,
                ack,
                false,
                false,
                b"received",
            ))
            .await
            .unwrap();
        // Read the payload before resetting: this also waits for the actor to
        // move it through the smoltcp receive buffer into the application bridge.
        let mut payload = [0; 8];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"received");
        incoming
            .send(reply_packet(local_port, 109, ack, false, true, &[]))
            .await
            .unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            stream.write_all(b"after reset").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(slots.available_permits(), 1);
        stop.close();
        task.await.unwrap();
    })
    .await
    .unwrap();
}
fn reply_packet(
    port: u16,
    seq: i32,
    ack: TcpSeqNumber,
    syn: bool,
    rst: bool,
    payload: &[u8],
) -> Packet<gotatun::packet::Ip> {
    let mut bytes = bytes::BytesMut::zeroed(40 + payload.len());
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len((40 + payload.len()) as u16);
    ip.set_hop_limit(64);
    ip.set_next_header(IpProtocol::Tcp);
    ip.set_src_addr("198.51.100.7".parse().unwrap());
    ip.set_dst_addr("10.44.0.2".parse().unwrap());
    ip.fill_checksum();
    let source = ip.src_addr().into();
    let dest = ip.dst_addr().into();
    let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
    tcp.set_src_port(443);
    tcp.set_dst_port(port);
    tcp.set_seq_number(TcpSeqNumber(seq));
    tcp.set_ack_number(ack);
    tcp.set_ack(true);
    tcp.set_syn(syn);
    tcp.set_rst(rst);
    tcp.set_header_len(20);
    tcp.set_window_len(65535);
    tcp.payload_mut().copy_from_slice(payload);
    tcp.fill_checksum(&source, &dest);
    Packet::from_bytes(bytes).try_into_ip().unwrap()
}

#[tokio::test]
async fn idle_carrier_receive_follows_rebind_and_releases_old_sockets() {
    use crate::io::Factory;
    use gotatun::{
        packet::PacketBufPool,
        udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    };
    use std::future::Future;
    use tokio::{net::UdpSocket, time::timeout};
    timeout(Duration::from_secs(10), async {
        for ip in ["127.0.0.1", "::1"] {
            let remote = UdpSocket::bind((ip, 0)).await.unwrap();
            let mut factory = Factory {
                ipv4: true,
                ipv6: true,
                protector: None,
                protection_failed: Arc::new(AtomicBool::new(false)),
                stop: Stop::new(),
                carrier: watch::channel(None).0,
            };
            let (send, mut receive) = factory
                .bind(&UdpTransportFactoryParams {
                    addr: None,
                    port: 0,
                    #[cfg(target_os = "linux")]
                    fwmark: None,
                })
                .await
                .unwrap();
            let old = Arc::downgrade(factory.carrier.borrow().as_ref().unwrap());
            let mut bytes = [0; 32];
            send.send_to(
                Packet::from_bytes(bytes::BytesMut::from(&b"old request"[..])),
                remote.local_addr().unwrap(),
            )
            .await
            .unwrap();
            let (_, old_address) = remote.recv_from(&mut bytes).await.unwrap();
            let mut pool = PacketBufPool::new(1);
            let mut pending = Box::pin(receive.recv_from(&mut pool));
            std::future::poll_fn(|cx| {
                assert!(
                    pending.as_mut().poll(cx).is_pending(),
                    "no old socket traffic"
                );
                Poll::Ready(())
            })
            .await;
            factory.rebind().unwrap();
            send.send_to(
                Packet::from_bytes(bytes::BytesMut::from(&b"new socket"[..])),
                remote.local_addr().unwrap(),
            )
            .await
            .unwrap();
            let mut bytes = [0; 32];
            let (n, address) = remote.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], b"new socket");
            remote
                .send_to(b"reply on new socket", address)
                .await
                .unwrap();
            let (packet, _) = pending.await.unwrap();
            assert_eq!(&packet[..], b"reply on new socket");
            remote
                .send_to(b"delayed old reply", old_address)
                .await
                .unwrap();
            let (packet, _) = receive.recv_from(&mut pool).await.unwrap();
            assert_eq!(&packet[..], b"delayed old reply");
            assert!(
                timeout(Duration::from_millis(3200), receive.recv_from(&mut pool))
                    .await
                    .is_err()
            );
            assert!(
                old.upgrade().is_none(),
                "retired socket set must expire even without traffic"
            );
        }
    })
    .await
    .expect("idle receive must wake on carrier replacement");
}
