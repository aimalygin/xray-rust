//! `sockopt` on the sockets a `TransportDialer` opens.
#![cfg(unix)]

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    os::fd::RawFd,
    sync::{Arc, Mutex},
};

use tokio::{io::AsyncWriteExt, net::TcpListener};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    ConnectorConfig, HappyEyeballsConfig, RealityClientConfig, SocketHandle, SocketOptions,
    SocketProtector, TransportDialer, TransportError,
};

/// The platform's protector: records each socket it is handed.
#[derive(Default)]
struct Recorder(Mutex<Vec<RawFd>>);

impl SocketProtector for Recorder {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        self.0.lock().unwrap().push(socket.raw() as RawFd);
        Ok(())
    }
}

impl Recorder {
    fn sockets(&self) -> Vec<RawFd> {
        self.0.lock().unwrap().clone()
    }
}

fn get(fd: RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a socket the dialer keeps open while its stream lives,
    // and `value` is a local `c_int` of the size passed.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    value
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const KEEPALIVE_IDLE: libc::c_int = 4;
#[cfg(target_vendor = "apple")]
const KEEPALIVE_IDLE: libc::c_int = 0x10;

fn keepalive_idle(fd: RawFd) -> Option<libc::c_int> {
    (get(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE) != 0)
        .then(|| get(fd, libc::IPPROTO_TCP, KEEPALIVE_IDLE))
}

fn idle(seconds: i32) -> Arc<SocketOptions> {
    Arc::new(SocketOptions {
        tcp_keep_alive_idle: seconds,
        ..SocketOptions::default()
    })
}

fn target(addr: SocketAddr) -> Target {
    Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp)
}

#[tokio::test]
async fn options_go_on_after_the_platform_protector_on_every_tcp_dial() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let closed = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let refused = closed.local_addr().unwrap();
    drop(closed);
    let race = HappyEyeballsConfig {
        try_delay: std::time::Duration::from_millis(50),
        ..HappyEyeballsConfig::default()
    };
    for (candidates, happy_eyeballs) in [
        (vec![addr], None),
        (vec![refused, addr], None),
        (vec![refused, addr], Some(&race)),
    ] {
        let recorder = Arc::new(Recorder::default());
        let dialer = TransportDialer::system()
            .unwrap()
            .with_socket_protector(recorder.clone())
            .with_socket_options(idle(31));
        let stream = dialer
            .connect_resolved(
                &ConnectorConfig::Tcp,
                &target(addr),
                &candidates,
                happy_eyeballs,
            )
            .await
            .unwrap();
        let _ = listener.accept().await.unwrap();
        let sockets = recorder.sockets();
        assert!(!sockets.is_empty());
        // The socket that connected is the last one handed out.
        assert_eq!(
            keepalive_idle(*sockets.last().unwrap()),
            Some(31),
            "{candidates:?}"
        );
        drop(stream);
    }
}

#[tokio::test]
async fn later_options_replace_earlier_ones_and_keep_the_platform_protector() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorder = Arc::new(Recorder::default());
    let defaults = TransportDialer::system()
        .unwrap()
        .with_socket_protector(recorder.clone())
        .with_socket_options(Arc::new(SocketOptions::default()));
    let outbound = defaults.clone().with_socket_options(idle(17));
    assert_eq!(
        outbound
            .socket_options()
            .map(|options| options.tcp_keep_alive_idle),
        Some(17)
    );

    let first = defaults
        .connect_resolved(&ConnectorConfig::Tcp, &target(addr), &[addr], None)
        .await
        .unwrap();
    let _ = listener.accept().await.unwrap();
    let second = outbound
        .connect_resolved(&ConnectorConfig::Tcp, &target(addr), &[addr], None)
        .await
        .unwrap();
    let _ = listener.accept().await.unwrap();
    let sockets = recorder.sockets();
    assert_eq!(sockets.len(), 2);
    assert_eq!(keepalive_idle(sockets[0]), Some(45));
    assert_eq!(keepalive_idle(sockets[1]), Some(17));
    drop((first, second));
}

#[tokio::test]
async fn an_unbindable_interface_fails_tcp_and_reality_dials_before_any_byte() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_options(Arc::new(SocketOptions {
            interface: "xray-missing0".to_owned(),
            ..SocketOptions::default()
        }));
    let reality = ConnectorConfig::Reality(RealityClientConfig {
        server_name: "reality.example".to_owned(),
        fingerprint: "chrome".to_owned(),
        public_key: [1; 32],
        short_id: vec![1, 2, 3, 4],
        spider_x: String::new(),
        mldsa65_verify: None,
    });
    for connector in [ConnectorConfig::Tcp, reality] {
        // A REALITY dial with one candidate opens the dialer's own socket.
        let (server, candidates) = (target(addr), [addr]);
        let dial = dialer.connect_resolved(&connector, &server, &candidates, None);
        let Err(error) = tokio::time::timeout(std::time::Duration::from_secs(5), dial)
            .await
            .expect("the dial went past its socket options")
        else {
            panic!("dial succeeded without its interface");
        };
        assert!(
            matches!(&error, TransportError::SocketProtection(error) if error.to_string().contains("failed to bind to interface")),
            "{error}"
        );
    }
    let accepted =
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await;
    assert!(accepted.is_err(), "a socket connected");
}

/// Linux's `TCP_FASTOPEN_CONNECT` defers the handshake to the first write,
/// and until then the kernel knows no peer; the dialer reports the address it
/// connected to, as Go's `Conn.RemoteAddr` does. The kernel defers only with
/// a cached cookie or with `net.ipv4.tcp_fastopen` bit 4 set, so run this in
/// a network namespace with `net.ipv4.tcp_fastopen=5` to cover that case.
#[tokio::test]
async fn the_peer_a_dialer_reports_is_the_address_it_connected_to() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_options(Arc::new(SocketOptions {
            tcp_fast_open: 256,
            ..SocketOptions::default()
        }));
    let (mut stream, peer) = dialer
        .connect_raw_stream_with_peer(&ConnectorConfig::Tcp, &target(addr), &[addr], None)
        .await
        .unwrap();
    assert_eq!(peer, addr);
    stream.write_all(b"x").await.unwrap();
    let _ = listener.accept().await.unwrap();
}
