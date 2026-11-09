use super::*;

const ID: [u8; 8] = *b"clientid";

#[test]
fn readers_keep_echo_replies_that_are_not_the_systems_own() {
    let reply = message::echo(message::ECHO_REPLY_V4, 7, 1, b"packet");
    assert_eq!(
        accept_echo(&reply, false, true, true, 7, &ID),
        Some(&b"packet"[..])
    );
    // Where the system writes its own identifier, any is taken.
    assert_eq!(
        accept_echo(&reply, false, true, false, 8, &ID),
        Some(&b"packet"[..])
    );
    assert_eq!(accept_echo(&reply, false, true, true, 8, &ID), None);
    // A raw socket takes its own only, after the IPv4 header.
    let mut raw = vec![0x45u8; 20];
    raw.extend_from_slice(&reply);
    assert_eq!(
        accept_echo(&raw, false, false, true, 7, &ID),
        Some(&b"packet"[..])
    );
    assert_eq!(accept_echo(&raw, false, false, true, 8, &ID), None);
    // A request, or a reply carrying the client's id first, is dropped.
    let request = message::echo(message::ECHO_REQUEST_V4, 7, 1, b"packet");
    assert_eq!(accept_echo(&request, false, true, false, 7, &ID), None);
    let mut echoed = ID.to_vec();
    echoed.extend_from_slice(b"packet");
    let own = message::echo(message::ECHO_REPLY_V4, 7, 1, &echoed);
    assert_eq!(accept_echo(&own, false, true, false, 7, &ID), None);
    // Exactly the id, with nothing after it, is a packet.
    let bare = message::echo(message::ECHO_REPLY_V4, 7, 1, &ID);
    assert_eq!(
        accept_echo(&bare, false, true, false, 7, &ID),
        Some(&ID[..])
    );
    // ICMPv6 replies come without a header.
    let v6 = message::echo(message::ECHO_REPLY_V6, 7, 1, b"six");
    assert_eq!(
        accept_echo(&v6, true, false, true, 7, &ID),
        Some(&b"six"[..])
    );
    assert_eq!(accept_echo(&reply, true, true, false, 7, &ID), None);
}

#[test]
fn a_socket_tells_its_replies_by_identifier_where_it_keeps_it() {
    assert!(own_identifier(false));
    assert_eq!(own_identifier(true), cfg!(target_vendor = "apple"));
}

#[tokio::test]
async fn a_datagram_client_sends_and_drops_the_systems_echo_of_it() {
    let config = XicmpConfig {
        dgram: true,
        ips: vec![],
    };
    // Datagram ICMP sockets may be refused, as by Linux's default
    // ping_group_range; nothing to check then.
    let Ok(client) = XicmpClient::connect(&config, "127.0.0.1".parse().unwrap(), None).await else {
        return;
    };
    client.send(b"first packet").unwrap();
    // The largest packet an echo carries goes out; one byte more is
    // dropped, as Xray-core drops it, without taking a sequence number.
    client.send(&vec![0u8; MAX_PACKET - OVERHEAD]).unwrap();
    client.send(&vec![0u8; MAX_PACKET - OVERHEAD + 1]).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(client.try_recv().is_none(), "the system's echo got through");
    assert_eq!(*client.shared.seq.lock().unwrap(), 3);
}

/// Apple systems return an IPv4 datagram socket's header unless told not
/// to, as Go's `icmp.ListenPacket` tells them.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn an_apple_ipv4_datagram_socket_reads_without_the_header() {
    use std::os::fd::AsRawFd;
    let Ok(socket) = open("127.0.0.1".parse().unwrap(), true, None) else {
        return;
    };
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the descriptor is open, and the value and length are live.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            0x17,
            std::ptr::addr_of_mut!(value).cast(),
            &mut length,
        )
    };
    // The system reports the flag it keeps, nonzero once set.
    assert_eq!(result, 0);
    assert_ne!(value, 0);
}

#[tokio::test]
async fn every_listed_address_gets_one_socket_and_draws_count_duplicates() {
    let config = XicmpConfig {
        dgram: true,
        ips: vec![
            "127.0.0.1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
        ],
    };
    let Ok(client) = XicmpClient::connect(&config, "192.0.2.1".parse().unwrap(), None).await else {
        return;
    };
    let ips: Vec<IpAddr> = client.shared.sockets.iter().map(|(ip, _)| *ip).collect();
    assert_eq!(
        ips,
        vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "127.0.0.2".parse().unwrap()
        ]
    );
    assert_eq!(client.shared.addresses.len(), 3);
}
