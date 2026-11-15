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
    let Ok((socket, _, _)) = open("127.0.0.1".parse().unwrap(), true, None) else {
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

/// The device defect of 0.10.0's candidates: inside a Network Extension
/// NECP defuncted a connected ICMP socket after its first echo request. On
/// Apple systems the socket is left unconnected, in either family.
#[cfg(target_vendor = "apple")]
#[test]
fn an_apple_socket_is_left_unconnected() {
    for address in ["127.0.0.1", "::1"] {
        let address: IpAddr = address.parse().unwrap();
        let (socket, _, connected) = open(address, true, None).unwrap();
        assert!(!connected, "{address}");
        assert_eq!(
            socket.peer_addr().unwrap_err().kind(),
            io::ErrorKind::NotConnected,
            "{address}"
        );
    }
}

/// Elsewhere the socket is connected to its address, as before.
#[cfg(not(target_vendor = "apple"))]
#[test]
fn elsewhere_a_socket_is_connected_to_its_address() {
    let address: IpAddr = "127.0.0.1".parse().unwrap();
    let Ok((socket, _, connected)) = open(address, true, None) else {
        return;
    };
    assert!(connected);
    assert_eq!(socket.peer_addr().unwrap().ip(), address);
}

/// An unconnected socket reads every echo reply the system gets. A reply
/// from another address, even with the client's identifier and a packet in
/// it, is not the server's; the same from the server's address is.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn an_unconnected_socket_keeps_only_the_replies_from_its_address() {
    use socket2::{Domain, Protocol, Socket, Type};
    // Another address of this system, which echoes requests to it as well.
    let route = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    if route.connect("192.0.2.1:9").is_err() {
        return;
    }
    let other = route.local_addr().unwrap().ip();
    if other.is_loopback() || other.is_unspecified() {
        return;
    }
    let config = XicmpConfig {
        dgram: true,
        ips: vec![],
    };
    let server: IpAddr = "127.0.0.1".parse().unwrap();
    let client = XicmpClient::connect(&config, server, None).await.unwrap();
    let pinger = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).unwrap();
    let id = client.shared.id;
    let elsewhere = message::echo(message::ECHO_REQUEST_V4, id, 1, b"from elsewhere");
    pinger
        .send_to(&elsewhere, &SocketAddr::new(other, 0).into())
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        client.try_recv().is_none(),
        "another address's reply got through"
    );
    let from_server = message::echo(message::ECHO_REQUEST_V4, id, 2, b"from the server");
    pinger
        .send_to(&from_server, &SocketAddr::new(server, 0).into())
        .unwrap();
    let packet = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.data, b"from the server");
    assert_eq!(packet.from, SocketAddr::new(server, 0));
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
    let ips: Vec<IpAddr> = client
        .shared
        .sockets
        .iter()
        .map(|socket| socket.address)
        .collect();
    assert_eq!(
        ips,
        vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "127.0.0.2".parse().unwrap()
        ]
    );
    assert_eq!(client.shared.addresses.len(), 3);
}

/// The interfaces a test binds to: the loopback, which every system has,
/// and another of this one's. Apple systems grant datagram ICMP sockets
/// to any process, so the tests below open theirs unconditionally.
#[cfg(target_vendor = "apple")]
fn two_interfaces() -> (std::num::NonZeroU32, std::num::NonZeroU32) {
    let mut indexes = Vec::new();
    // SAFETY: the list is read up to its zero entry and freed once.
    unsafe {
        let list = libc::if_nameindex();
        assert!(!list.is_null());
        let mut entry = list;
        while (*entry).if_index != 0 {
            indexes.push((*entry).if_index);
            entry = entry.add(1);
        }
        libc::if_freenameindex(list);
    }
    // SAFETY: a NUL-terminated name.
    let loopback = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
    let other = indexes
        .into_iter()
        .find(|index| *index != loopback)
        .expect("an interface besides lo0");
    (
        std::num::NonZeroU32::new(loopback).unwrap(),
        std::num::NonZeroU32::new(other).unwrap(),
    )
}

/// Stands in for NECP inside a Network Extension: binds the process's UDP
/// sockets, which take a port, to the interface the tunnel runs over. It
/// leaves the ICMP sockets alone, so that the tests see what the client
/// binds them to. Zero leaves the UDP sockets unbound, as outside one. With
/// `all`, it binds the ICMP sockets too, as `sockopt.interface` does.
#[cfg(target_vendor = "apple")]
#[derive(Default)]
struct ScopesUdp {
    udp: std::sync::atomic::AtomicU32,
    all: Option<std::num::NonZeroU32>,
    asked: std::sync::atomic::AtomicUsize,
}

#[cfg(target_vendor = "apple")]
impl ScopesUdp {
    fn to(index: std::num::NonZeroU32) -> Self {
        let scopes = Self::default();
        scopes.set(Some(index));
        scopes
    }

    fn set(&self, index: Option<std::num::NonZeroU32>) {
        self.udp.store(
            index.map_or(0, std::num::NonZeroU32::get),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(target_vendor = "apple")]
impl SocketProtector for ScopesUdp {
    fn protect(&self, socket: crate::SocketHandle) -> io::Result<()> {
        use std::{os::fd::BorrowedFd, sync::atomic::Ordering};
        // SAFETY: the socket stays open for this call.
        let fd = unsafe { BorrowedFd::borrow_raw(socket.raw() as std::os::fd::RawFd) };
        let socket = socket2::SockRef::from(&fd);
        let local = socket.local_addr()?.as_socket().expect("an inet socket");
        let index = if local.port() == 0 {
            match self.all {
                Some(index) => Some(index),
                None => return Ok(()),
            }
        } else {
            self.asked.fetch_add(1, Ordering::SeqCst);
            std::num::NonZeroU32::new(self.udp.load(Ordering::SeqCst))
        };
        if local.is_ipv4() {
            socket.bind_device_by_index_v4(index)
        } else {
            socket.bind_device_by_index_v6(index)
        }
    }
}

/// The ICMP socket takes the interface the system scopes the process's UDP
/// sockets to, in either family.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn an_icmp_socket_takes_the_interface_the_system_scopes_udp_to() {
    let (loopback, _) = two_interfaces();
    for address in ["127.0.0.1", "::1"] {
        let address: IpAddr = address.parse().unwrap();
        let scopes = ScopesUdp::to(loopback);
        let (socket, scope, _) = open(address, true, Some(&scopes)).unwrap();
        assert_eq!(
            scope::system(address, Some(&scopes)).unwrap(),
            Some(loopback)
        );
        assert_eq!(
            scope::bound(&socket, address).unwrap(),
            Some(loopback),
            "{address}"
        );
        assert!(scope.follows(), "{address}");
    }
}

/// Outside a Network Extension the system scopes no UDP socket, and the
/// ICMP socket follows the routes unbound, as before and as in Xray-core.
/// Its sends still ask, and it takes the interface once the system scopes
/// UDP sockets, as when a dial came before the tunnel's settings.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn an_icmp_socket_stays_unbound_while_udp_sockets_are() {
    let (loopback, _) = two_interfaces();
    let scopes = ScopesUdp::default();
    let address: IpAddr = "127.0.0.1".parse().unwrap();
    let (socket, scope, _) = open(address, true, Some(&scopes)).unwrap();
    assert_eq!(scope::bound(&socket, address).unwrap(), None);
    assert!(scope.follows());
    let later = std::time::Instant::now() + scope::RECHECK;
    scope.refresh_at(later, &socket, address, Some(&scopes));
    assert_eq!(scope::bound(&socket, address).unwrap(), None);
    scopes.set(Some(loopback));
    scope.refresh_at(later + scope::RECHECK, &socket, address, Some(&scopes));
    assert_eq!(scope::bound(&socket, address).unwrap(), Some(loopback));
    assert_eq!(scopes.asked(), 3);
}

/// `sockopt.interface` binds the ICMP socket through the protector; that
/// interface stays, whatever the system gives UDP sockets.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn an_icmp_socket_the_protector_bound_keeps_its_interface() {
    let (loopback, other) = two_interfaces();
    let scopes = ScopesUdp {
        all: Some(loopback),
        ..ScopesUdp::to(other)
    };
    let address: IpAddr = "127.0.0.1".parse().unwrap();
    let (socket, scope, _) = open(address, true, Some(&scopes)).unwrap();
    assert_eq!(scope::bound(&socket, address).unwrap(), Some(loopback));
    assert!(!scope.follows());
    assert_eq!(scopes.asked(), 0, "the system was asked");
}

/// Wi-Fi to cellular: the system scopes UDP sockets to the new interface,
/// and the ICMP socket moves there at the first send a period after it last
/// asked. Where the system scopes none for a while, it stays: unbound, its
/// requests would go into the tunnel.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn an_icmp_socket_moves_with_the_interface_the_system_scopes_udp_to() {
    let (loopback, other) = two_interfaces();
    let scopes = ScopesUdp::to(loopback);
    let address: IpAddr = "127.0.0.1".parse().unwrap();
    let (socket, scope, _) = open(address, true, Some(&scopes)).unwrap();
    let opened = std::time::Instant::now();
    scopes.set(Some(other));
    scope.refresh_at(opened, &socket, address, Some(&scopes));
    assert_eq!(scope::bound(&socket, address).unwrap(), Some(loopback));
    assert_eq!(scopes.asked(), 1, "asked again within the period");
    let later = opened + scope::RECHECK;
    scope.refresh_at(later, &socket, address, Some(&scopes));
    assert_eq!(scope::bound(&socket, address).unwrap(), Some(other));
    scopes.set(None);
    scope.refresh_at(later + scope::RECHECK, &socket, address, Some(&scopes));
    assert_eq!(scope::bound(&socket, address).unwrap(), Some(other));
    assert_eq!(scopes.asked(), 3);
}

/// The client's sends are what ask again: the first one past the period
/// moves the socket, and it still goes out.
#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn a_send_moves_the_socket_once_the_period_has_passed() {
    let (loopback, other) = two_interfaces();
    let scopes = Arc::new(ScopesUdp::to(loopback));
    let config = XicmpConfig {
        dgram: true,
        ips: vec![],
    };
    let protector: Arc<dyn SocketProtector> = scopes.clone();
    let client = XicmpClient::connect(&config, "127.0.0.1".parse().unwrap(), Some(protector))
        .await
        .unwrap();
    let address: IpAddr = "127.0.0.1".parse().unwrap();
    let socket = &client.shared.sockets[0].socket;
    client.send(b"on loopback").unwrap();
    assert_eq!(scope::bound(socket, address).unwrap(), Some(loopback));
    scopes.set(Some(other));
    tokio::time::sleep(scope::RECHECK).await;
    // Whether the other interface routes to the loopback address is the
    // system's to say; only the binding is checked.
    let _ = client.send(b"moved");
    assert_eq!(scope::bound(socket, address).unwrap(), Some(other));
    assert_eq!(*client.shared.seq.lock().unwrap(), 3);
}
