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
