use super::*;
use crate::xdns::{message, XdnsDomain, XdnsResolver};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

fn domain(len_limit: i32) -> XdnsDomain {
    XdnsDomain {
        name: "t.example.com".into(),
        len_limit,
        label_limit: 63,
        types: vec![],
        edns0: 1232,
    }
}

fn config(resolvers: Vec<XdnsResolver>, len_limit: i32) -> XdnsConfig {
    XdnsConfig {
        domains: vec![domain(len_limit)],
        resolvers,
        extra_poll: 0,
    }
}

/// The bytes a query's name carries.
fn carried(query: &[u8], len_limit: i32) -> (Vec<u8>, u16, Option<u16>) {
    let (name, qtype, edns0) = message::question(query).unwrap();
    let domain = Domain::new("t.example.com", len_limit, 63, &[qtype], 0).unwrap();
    (domain.decode(&name), qtype, edns0)
}

async fn next_query(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; 512];
    let (length, from) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .expect("a query")
        .unwrap();
    buf.truncate(length);
    (buf, from)
}

#[tokio::test]
async fn a_packet_rides_in_one_query_under_the_client_id() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = XdnsClient::connect(
        &config(
            vec![XdnsResolver::Udp(vec![resolver.local_addr().unwrap()])],
            255,
        ),
        None,
    )
    .await
    .unwrap();
    client.send(b"hello").unwrap();
    let (query, _) = next_query(&resolver).await;
    let (data, qtype, edns0) = carried(&query, 255);
    // No types configured asks for TXT; the domain's size goes out in OPT.
    assert_eq!(qtype, 16);
    assert_eq!(edns0, Some(1232));
    let mut id = client.shared.client_id;
    id[0] |= type_bits(16);
    assert_eq!(data[..8], id);
    assert_eq!(data[8], 3);
    assert_eq!(&data[12..], b"hello");

    assert!(client.send(&[]).is_err());
    assert!(client.send(&[0; 4097]).is_err());
}

#[tokio::test]
async fn a_large_packet_goes_out_in_fragments() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = XdnsClient::connect(
        &config(
            vec![XdnsResolver::Udp(vec![resolver.local_addr().unwrap()])],
            80,
        ),
        None,
    )
    .await
    .unwrap();
    let capacity = Domain::new("t.example.com", 80, 63, &[16], 0)
        .unwrap()
        .capacity();
    let packet: Vec<u8> = (0..300).map(|i| i as u8).collect();
    client.send(&packet).unwrap();
    let count = packet.len().div_ceil(capacity - 15);
    let mut joined = Vec::new();
    let mut random = None;
    for index in 0..count {
        let (query, _) = next_query(&resolver).await;
        let (data, ..) = carried(&query, 80);
        assert_eq!(data[8], 0xC3);
        // The padding is drawn once for all of a packet's fragments.
        assert_eq!(*random.get_or_insert(data[9..12].to_vec()), data[9..12]);
        assert_eq!(data[12], 1, "the first fragment id");
        assert_eq!(usize::from(data[13]), index);
        assert_eq!(usize::from(data[14]), count);
        joined.extend_from_slice(&data[15..]);
    }
    assert_eq!(joined, packet);
}

#[tokio::test]
async fn answers_bring_packets_and_then_polls() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = resolver.local_addr().unwrap();
    let client = XdnsClient::connect(&config(vec![XdnsResolver::Udp(vec![address])], 255), None)
        .await
        .unwrap();
    client.send(b"ping").unwrap();
    let (query, from) = next_query(&resolver).await;
    let answer = message::txt_answer(&query, &message::frame(&[b"pong", b"again"]));
    resolver.send_to(&answer, from).await.unwrap();
    for expected in [&b"pong"[..], b"again"] {
        let packet = timeout(WAIT, client.recv()).await.unwrap().unwrap();
        assert_eq!(packet.data, expected);
        assert_eq!(packet.from, address);
    }
    // An answer that carried packets starts the polls: eight bytes of
    // padding after the id.
    let (query, _) = next_query(&resolver).await;
    let (data, ..) = carried(&query, 255);
    assert_eq!((data.len(), data[8]), (17, 8));
}

/// An answer from an address that is not the resolver's is not read, though
/// it is well formed and names the tunnel's domain.
#[tokio::test]
async fn an_answer_from_another_address_is_dropped() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = resolver.local_addr().unwrap();
    let client = XdnsClient::connect(&config(vec![XdnsResolver::Udp(vec![address])], 255), None)
        .await
        .unwrap();
    client.send(b"ping").unwrap();
    let (query, from) = next_query(&resolver).await;
    let forged = message::txt_answer(&query, &message::frame(&[b"forged"]));
    stranger.send_to(&forged, from).await.unwrap();
    let answer = message::txt_answer(&query, &message::frame(&[b"pong"]));
    resolver.send_to(&answer, from).await.unwrap();
    let packet = timeout(WAIT, client.recv()).await.unwrap().unwrap();
    assert_eq!(packet.data, b"pong");
}

#[tokio::test]
async fn queries_go_to_the_resolver_that_sent_fewer() {
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = XdnsClient::connect(
        &config(
            vec![
                XdnsResolver::Udp(vec![first.local_addr().unwrap()]),
                XdnsResolver::Udp(vec![second.local_addr().unwrap()]),
            ],
            255,
        ),
        None,
    )
    .await
    .unwrap();
    // Xray's balance: 0, 1, 1, 0, 0, 1.
    for i in 0..6u8 {
        client.send(&[i]).unwrap();
    }
    let mut order = Vec::new();
    for _ in 0..6 {
        tokio::select! {
            (query, _) = next_query(&first) => order.push((0, carried(&query, 255).0[12])),
            (query, _) = next_query(&second) => order.push((1, carried(&query, 255).0[12])),
        }
    }
    order.sort_by_key(|(_, packet)| *packet);
    let resolvers: Vec<u8> = order.iter().map(|(resolver, _)| *resolver).collect();
    assert_eq!(resolvers, [0, 1, 1, 0, 0, 1]);
}

#[tokio::test]
async fn tcp_frames_each_message_and_connects_again() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = XdnsClient::connect(&config(vec![XdnsResolver::Tcp(vec![address])], 255), None)
        .await
        .unwrap();
    for round in 0..2u8 {
        // The first query takes the connection opened with the client.
        client.send(&[round]).unwrap();
        let (mut connection, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        let length = connection.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        connection.read_exact(&mut query).await.unwrap();
        assert_eq!(carried(&query, 255).0[12..], [round]);
        let answer = message::txt_answer(&query, &message::frame(&[&[round, round]]));
        connection.write_u16(answer.len() as u16).await.unwrap();
        connection.write_all(&answer).await.unwrap();
        let packet = timeout(WAIT, client.recv()).await.unwrap().unwrap();
        assert_eq!(packet.data, [round, round]);
        assert_eq!(packet.from, address);
        // The resolver hangs up; the next query connects again.
        drop(connection);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
