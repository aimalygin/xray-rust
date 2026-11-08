use super::*;
use crate::xdns::{message, XdnsConfig, XdnsDomain, XdnsResolver};
use std::{future::poll_fn, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

fn transmit(peer: SocketAddr, contents: &[u8], segment_size: Option<usize>) -> udp::Transmit<'_> {
    udp::Transmit {
        destination: peer,
        ecn: None,
        contents,
        segment_size,
        src_ip: None,
    }
}

#[tokio::test]
async fn quinn_sees_one_packet_at_a_time_from_its_peer() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = XdnsConfig {
        domains: vec![XdnsDomain {
            name: "t.example.com".into(),
            len_limit: 255,
            label_limit: 63,
            types: vec![16],
            edns0: 4096,
        }],
        resolvers: vec![XdnsResolver::Udp(vec![resolver.local_addr().unwrap()])],
        extra_poll: 0,
    };
    let client = Arc::new(XdnsClient::connect(&config, None).await.unwrap());
    let peer: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let socket = socket(client, peer);
    // Path MTU discovery stays off, as quic-go's is on a masked conn.
    assert!(socket.may_fragment());
    assert_eq!(socket.max_transmit_segments(), 1);
    assert_eq!(socket.max_receive_segments(), 1);
    assert_eq!(socket.local_addr().unwrap(), "0.0.0.0:0".parse().unwrap());
    assert!(socket
        .try_send(&transmit(peer, &[1; 2400], Some(1200)))
        .is_err());
    socket.try_send(&transmit(peer, b"initial", None)).unwrap();
    let mut buf = vec![0u8; 512];
    let (length, from) = timeout(Duration::from_secs(5), resolver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let answer = message::txt_answer(&buf[..length], &message::frame(&[b"one", b"two"]));
    resolver.send_to(&answer, from).await.unwrap();
    let mut storage = vec![vec![0u8; 1500]; 4];
    let mut meta = vec![udp::RecvMeta::default(); 4];
    let count = timeout(
        Duration::from_secs(5),
        poll_fn(|cx| {
            let mut bufs: Vec<IoSliceMut<'_>> =
                storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            socket.poll_recv(cx, &mut bufs, &mut meta)
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let got: Vec<&[u8]> = (0..count).map(|i| &storage[i][..meta[i].len]).collect();
    assert_eq!(got, [&b"one"[..], b"two"]);
    // The packets report the carrier's peer, not the resolver.
    assert!(meta[..count].iter().all(|meta| meta.addr == peer));
}
