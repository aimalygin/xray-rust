use super::*;
use quinn::Runtime as _;

#[tokio::test]
async fn reaches_ipv4_through_a_dual_stack_socket_and_reports_the_servers_family() {
    let udp = crate::realm::RealmUdp::open(crate::realm::RealmFamily::Dual, None).unwrap();
    if !udp.dual_stack {
        return;
    }
    let raw = quinn::TokioRuntime
        .wrap_udp_socket(udp.into_std().unwrap())
        .unwrap();
    let logical: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let socket = wrap(raw, logical).unwrap();
    assert!(socket.local_addr().unwrap().is_ipv4());
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut poller = socket.clone().create_io_poller();
    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .unwrap();
    socket
        .try_send(&udp::Transmit {
            destination: peer.local_addr().unwrap(),
            ecn: None,
            contents: b"over the mapped address",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    let mut buf = [0u8; 64];
    let (length, from) = peer.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..length], b"over the mapped address");
    peer.send_to(b"back", from).unwrap();
    let mut storage = [0u8; 64];
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [udp::RecvMeta::default()];
    let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(meta[0].addr, peer.local_addr().unwrap());
}
