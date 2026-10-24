//! `socks` outbound through xray-rust's own password-protected SOCKS inbound.
//!
//! One core runs both hops: `client-in` routes everything to the `socks`
//! outbound, which dials `upstream-in` on a fixed loopback port; `upstream-in`
//! authenticates with RFC 1929 and forwards to Freedom.

use super::*;

fn socks_chain_config(upstream_port: u16, pass: &str) -> CoreConfig {
    let raw = format!(
        r#"{{
        "inbounds": [
            {{"tag": "client-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
             "settings": {{"auth": "noauth", "udp": true}}}},
            {{"tag": "upstream-in", "protocol": "socks", "listen": "127.0.0.1",
             "port": {upstream_port},
             "settings": {{"auth": "password", "udp": true,
                "accounts": [{{"user": "synthetic-user", "pass": "synthetic-pass"}}]}}}}
        ],
        "outbounds": [
            {{"tag": "direct", "protocol": "freedom"}},
            {{"tag": "via-socks", "protocol": "socks",
             "settings": {{"address": "127.0.0.1", "port": {upstream_port},
                "user": "synthetic-user", "pass": "{pass}"}}}}
        ],
        "routing": {{"rules": [
            {{"type": "field", "inboundTag": ["client-in"], "outboundTag": "via-socks"}}
        ]}}
    }}"#
    );
    parse_xray_json(&raw)
        .expect("synthetic SOCKS chain config parses")
        .config
}

async fn start_socks_chain(pass: &str) -> (Core, SocketAddr) {
    let mut core = Core::new(socks_chain_config(allocate_unused_loopback_port(), pass)).unwrap();
    core.start().await.unwrap();
    let client_in = core.inbound_addr(Some("client-in")).unwrap();
    (core, client_in)
}

/// No-auth SOCKS5 CONNECT to an IPv4 target; returns the reply code.
async fn socks5_connect_ipv4(client: &mut TcpStream, target: SocketAddr) -> u8 {
    let SocketAddr::V4(target) = target else {
        panic!("echo servers bind IPv4 loopback");
    };
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    reply[1]
}

#[tokio::test]
async fn socks_outbound_tunnels_tcp_through_a_password_upstream() {
    timeout(Duration::from_secs(5), async {
        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let (mut core, client_in) = start_socks_chain("synthetic-pass").await;

        let mut client = TcpStream::connect(client_in).await.unwrap();
        assert_eq!(socks5_connect_ipv4(&mut client, echo_addr).await, 0);
        client
            .write_all(b"through the socks outbound")
            .await
            .unwrap();
        let mut echoed = [0; 26];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through the socks outbound");

        drop(client);
        core.stop().await.unwrap();
        timeout(Duration::from_secs(1), echo_handle)
            .await
            .unwrap()
            .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_fails_the_flow_when_the_upstream_rejects_its_password() {
    timeout(Duration::from_secs(5), async {
        let (echo_addr, echo_handle) = spawn_echo_server().await;
        let (mut core, client_in) = start_socks_chain("wrong-pass").await;

        let mut client = TcpStream::connect(client_in).await.unwrap();
        assert_ne!(
            socks5_connect_ipv4(&mut client, echo_addr).await,
            0,
            "a rejected upstream login must not open the tunnel"
        );

        drop(client);
        core.stop().await.unwrap();
        echo_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_outbound_refuses_udp() {
    timeout(Duration::from_secs(5), async {
        let (echo_addr, echo_handle) = spawn_udp_echo_server().await;
        let (mut core, client_in) = start_socks_chain("synthetic-pass").await;

        let mut control = TcpStream::connect(client_in).await.unwrap();
        let relay_addr = socks5_udp_associate(&mut control).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = Target::new(
            RoutingTargetAddr::Ip(echo_addr.ip()),
            echo_addr.port(),
            RoutingNetwork::Udp,
        );
        let request = encode_socks5_udp_datagram(&target, b"udp via socks").unwrap();
        client.send_to(&request, relay_addr).await.unwrap();
        let mut response = [0; 2048];
        assert!(
            timeout(Duration::from_millis(300), client.recv_from(&mut response))
                .await
                .is_err(),
            "UDP routed to the socks outbound must not be relayed"
        );

        drop(control);
        core.stop().await.unwrap();
        echo_handle.abort();
    })
    .await
    .unwrap();
}
