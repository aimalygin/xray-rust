//! The HTTP inbound as Xray-core's HTTP server answers: `CONNECT` answered
//! before routing, accounts naming the user, and sniffing.

use super::*;

const HTTP_INBOUND_CONFIG: &str = r#"{
    "inbounds": [
        {"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 0,
         "sniffing": {"enabled": true, "destOverride": ["http"], "routeOnly": true}},
        {"tag": "auth-in", "protocol": "http", "listen": "127.0.0.1", "port": 0,
         "settings": {"accounts": [{"user": "alice", "pass": "secret"},
                                   {"user": "bob", "pass": "secret"}]}}
    ],
    "outbounds": [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}
    ],
    "routing": {"rules": [
        {"protocol": ["bittorrent"], "outboundTag": "block"},
        {"domain": ["full:blocked.example"], "outboundTag": "block"},
        {"port": "80", "outboundTag": "block"},
        {"user": ["bob"], "outboundTag": "block"}
    ]}
}"#;

const ESTABLISHED: &str = "HTTP/1.1 200 Connection established\r\n\r\n";

async fn start_http_inbound_core() -> Core {
    let config = parse_xray_json(HTTP_INBOUND_CONFIG)
        .expect("synthetic HTTP inbound config parses")
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// Whatever arrives until the connection closes or goes quiet.
async fn rest(client: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buffer = [0; 1024];
    while let Ok(Ok(read)) = timeout(Duration::from_secs(2), client.read(&mut buffer)).await {
        if read == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..read]);
    }
    received
}

#[tokio::test]
async fn connect_is_answered_before_routing_as_xray_core_answers_it() {
    timeout(Duration::from_secs(15), async {
        let core = start_http_inbound_core().await;
        let http = core.inbound_addr(Some("http-in")).unwrap();

        let (echo_addr, _echo_handle) = spawn_echo_server().await;
        let (mut client, head) =
            http_proxy_head(http, &format!("CONNECT {echo_addr} HTTP/1.1\r\n\r\n")).await;
        assert_eq!(head, ESTABLISHED);
        assert_echoes(&mut client, b"plain bytes, no protocol").await;

        // A tunnel that cannot open still got its 200, then only closes.
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        let (mut client, head) =
            http_proxy_head(http, &format!("CONNECT {closed_addr} HTTP/1.1\r\n\r\n")).await;
        assert_eq!(head, ESTABLISHED);
        assert_eq!(rest(&mut client).await, b"");

        // A target without a port goes to port 80, which the rules block.
        let (mut client, head) =
            http_proxy_head(http, "CONNECT example.com HTTP/1.1\r\n\r\n").await;
        assert_eq!(head, ESTABLISHED);
        assert!(rest(&mut client).await.starts_with(b"HTTP/1.1 403 Forbidden"));

        // Plain HTTP forwarding is not implemented, and a request that does
        // not parse is closed without a reply.
        let (_, head) = http_proxy_head(http, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert_eq!(
            head,
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n"
        );
        let (_, head) = http_proxy_head(http, "CONNECT example.com:443\r\n\r\n").await;
        assert_eq!(head, "");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_inbound_tunnels_are_sniffed() {
    timeout(Duration::from_secs(15), async {
        let core = start_http_inbound_core().await;
        let http = core.inbound_addr(Some("http-in")).unwrap();
        let tunnel = |payload: Vec<u8>| async move {
            let (echo_addr, _echo_handle) = spawn_echo_server().await;
            let (mut client, head) =
                http_proxy_head(http, &format!("CONNECT {echo_addr} HTTP/1.1\r\n\r\n")).await;
            assert_eq!(head, ESTABLISHED);
            client.write_all(&payload).await.unwrap();
            rest(&mut client).await
        };

        let mut handshake = vec![19];
        handshake.extend_from_slice(b"BitTorrent protocol");
        handshake.extend_from_slice(&[0; 48]);
        assert!(tunnel(handshake).await.starts_with(b"HTTP/1.1 403"));
        // `destOverride` routes the request by its sniffed host.
        let blocked = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n".to_vec();
        assert!(tunnel(blocked).await.starts_with(b"HTTP/1.1 403"));
        let allowed = b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n".to_vec();
        assert_eq!(tunnel(allowed.clone()).await, allowed);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_accounts_require_basic_credentials_and_name_the_user() {
    timeout(Duration::from_secs(15), async {
        let core = start_http_inbound_core().await;
        let auth = core.inbound_addr(Some("auth-in")).unwrap();
        let connect = |target: SocketAddr, credentials: Option<&'static str>| async move {
            let authorization = credentials
                .map(|value| format!("Proxy-Authorization: Basic {value}\r\n"))
                .unwrap_or_default();
            http_proxy_head(
                auth,
                &format!("CONNECT {target} HTTP/1.1\r\n{authorization}\r\n"),
            )
            .await
        };
        let required = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
        let (echo_addr, _echo_handle) = spawn_echo_server().await;
        assert_eq!(connect(echo_addr, None).await.1, required);
        // alice:wrong
        assert_eq!(connect(echo_addr, Some("YWxpY2U6d3Jvbmc=")).await.1, required);

        // alice:secret
        let (mut client, head) = connect(echo_addr, Some("YWxpY2U6c2VjcmV0")).await;
        assert_eq!(head, ESTABLISHED);
        assert_echoes(&mut client, b"hello alice").await;

        // bob:secret, whom a `user` rule blocks.
        let (echo_addr, _echo_handle) = spawn_echo_server().await;
        let (mut client, head) = connect(echo_addr, Some("Ym9iOnNlY3JldA==")).await;
        assert_eq!(head, ESTABLISHED);
        assert!(rest(&mut client).await.starts_with(b"HTTP/1.1 403"));
    })
    .await
    .unwrap();
}
