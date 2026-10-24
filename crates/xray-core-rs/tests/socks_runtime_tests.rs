//! `socks` outbound against the pinned Go Xray-core SOCKS5 server.
//!
//! One Xray process runs a password inbound with a synthetic account and a
//! no-auth inbound, both forwarding to Freedom. Freedom resolves through
//! Xray's DNS, whose `hosts` maps a test-only domain to the loopback echo
//! server, so a domain target is resolved on the Xray side only; the local
//! resolver accepts nothing but the SOCKS server name.
#[path = "hysteria_runtime/support.rs"]
mod hysteria_support;
use hysteria_support::{tcp_echo, Bootstrap, Protector};
use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use xray_core_rs::Core;
use xray_transport::TransportDialer;

const DEADLINE: Duration = Duration::from_secs(20);
const USER: &str = "synthetic-socks-user";
const PASS: &str = "synthetic-socks-pass";
const REMOTE_DOMAIN: &str = "echo.socks-interop.test";
const PAYLOAD_LEN: usize = 64 * 1024;

/// Pinned Xray with a password inbound and a no-auth inbound on loopback.
struct XrayServer {
    child: Child,
    directory: PathBuf,
    password: u16,
    noauth: u16,
}

impl XrayServer {
    async fn start() -> Self {
        let binary = std::env::var_os("XRAY_CLIENT_PROTOCOL_BINARY")
            .expect("run scripts/check-socks-interop.sh");
        let directory = std::env::temp_dir().join(format!(
            "xray-socks-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        // Hold both listeners until the config is written so the ports differ.
        let listeners = [(); 2].map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let [password, noauth] = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap().port());
        let config = json!({
            "log": {"loglevel": "debug"},
            "dns": {"hosts": {REMOTE_DOMAIN: "127.0.0.1"}},
            "inbounds": [
                {"listen": "127.0.0.1", "port": password, "protocol": "socks",
                 "settings": {"auth": "password", "accounts": [{"user": USER, "pass": PASS}]}},
                {"listen": "127.0.0.1", "port": noauth, "protocol": "socks",
                 "settings": {"auth": "noauth"}}
            ],
            "outbounds": [{"protocol": "freedom", "settings": {
                "domainStrategy": "UseIPv4",
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]
            }}]
        });
        std::fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        drop(listeners);
        let log = std::fs::File::create(directory.join("server.log")).unwrap();
        let child = Command::new(binary)
            .args(["run", "-config"])
            .arg(directory.join("config.json"))
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            directory,
            password,
            noauth,
        };
        server.wait_ready().await;
        server
    }

    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            assert!(self.child.try_wait().unwrap().is_none(), "Xray exited");
            if self.log().contains("core: Xray 26.7.28 started") {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Xray startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("server.log")).unwrap_or_default()
    }
}

impl Drop for XrayServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("pinned Xray log:\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Clone, Copy, Debug)]
enum Form {
    Flat,
    Servers,
}

/// Outbound settings in either Xray form; the server name is resolved by
/// `Bootstrap`, which rejects every other name.
fn outbound_settings(form: Form, port: u16, account: Option<(&str, &str)>) -> Value {
    match (form, account) {
        (Form::Flat, None) => json!({"address": "bootstrap.example", "port": port}),
        (Form::Flat, Some((user, pass))) => {
            json!({"address": "bootstrap.example", "port": port, "user": user, "pass": pass})
        }
        (Form::Servers, None) => {
            json!({"servers": [{"address": "bootstrap.example", "port": port}]})
        }
        (Form::Servers, Some((user, pass))) => json!({"servers": [{
            "address": "bootstrap.example", "port": port,
            "users": [{"user": user, "pass": pass}]
        }]}),
    }
}

fn core(settings: Value) -> (Core, Arc<Protector>, Arc<Bootstrap>) {
    let protector = Arc::new(Protector::default());
    let bootstrap = Arc::new(Bootstrap::default());
    let dialer =
        Arc::new(TransportDialer::system_with_socket_protector(Some(protector.clone())).unwrap());
    let profile = json!({
        "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
                      "settings": {"auth": "noauth"}}],
        "outbounds": [{"tag": "proxy", "protocol": "socks", "settings": settings}]
    });
    let config = xray_config::parse_xray_json(&profile.to_string())
        .unwrap()
        .config;
    (
        Core::with_runtime_dependencies(config, bootstrap.clone(), dialer).unwrap(),
        protector,
        bootstrap,
    )
}

enum Destination<'a> {
    Ipv4(SocketAddr),
    Domain(&'a str, u16),
}

/// No-auth CONNECT to the core's inbound; returns the stream and reply code.
async fn connect(proxy: SocketAddr, destination: Destination<'_>) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0];
    match destination {
        Destination::Ipv4(SocketAddr::V4(target)) => {
            request.push(1);
            request.extend_from_slice(&target.ip().octets());
            request.extend_from_slice(&target.port().to_be_bytes());
        }
        Destination::Ipv4(target) => panic!("not IPv4: {target}"),
        Destination::Domain(domain, port) => {
            request.extend_from_slice(&[3, domain.len() as u8]);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    (stream, reply[1])
}

/// Writes and reads concurrently so a large payload cannot stall on buffers.
async fn echo_round_trip(stream: &mut TcpStream, len: usize) {
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let mut received = vec![0; len];
    let (written, echoed) = tokio::join!(write.write_all(&payload), read.read_exact(&mut received));
    written.unwrap();
    echoed.unwrap();
    assert!(received == payload, "echoed bytes differ");
}

async fn assert_tunnels(settings: Value, echo: SocketAddr) {
    let (mut core, protector, bootstrap) = core(settings);
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let mut open = Vec::new();
    for destination in [
        Destination::Ipv4(echo),
        Destination::Domain(REMOTE_DOMAIN, echo.port()),
    ] {
        let (mut stream, reply) = connect(proxy, destination).await;
        assert_eq!(reply, 0, "the tunnel must open");
        echo_round_trip(&mut stream, PAYLOAD_LEN).await;
        open.push(stream);
    }
    assert!(protector.0.load(Ordering::SeqCst) > 0);
    assert!(bootstrap.0.load(Ordering::SeqCst) > 0);
    let snapshot = core.connection_snapshot();
    assert_eq!(snapshot.connections.len(), 2);
    assert!(snapshot
        .connections
        .iter()
        .all(|c| c.outbound_tag.as_deref() == Some("proxy")));
    drop(open);
    core.stop().await.unwrap();
}

/// The flow fails, and Xray logs `reason` for one more inbound connection.
async fn assert_refused(server: &XrayServer, settings: Value, echo: SocketAddr, reason: &str) {
    let before = server.log().matches(reason).count();
    let (mut core, _, _) = core(settings);
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let (_stream, reply) = connect(proxy, Destination::Ipv4(echo)).await;
    assert_ne!(reply, 0, "a rejected login must not open the tunnel");
    core.stop().await.unwrap();
    while server.log().matches(reason).count() == before {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_password_and_noauth_against_pinned_xray() {
    let server = XrayServer::start().await;
    timeout(DEADLINE * 3, async {
        let (echo, _echo) = tcp_echo().await;
        assert_eq!(echo.ip(), Ipv4Addr::LOCALHOST);
        for form in [Form::Flat, Form::Servers] {
            eprintln!("SOCKS outbound form: {form:?}");
            let account = Some((USER, PASS));
            assert_tunnels(outbound_settings(form, server.password, account), echo).await;
            eprintln!("password passed");
            assert_tunnels(outbound_settings(form, server.noauth, None), echo).await;
            eprintln!("noauth passed");
            let wrong = Some((USER, "synthetic-wrong-pass"));
            let settings = outbound_settings(form, server.password, wrong);
            assert_refused(&server, settings, echo, "invalid username or password").await;
            eprintln!("wrong password refused");
            let settings = outbound_settings(form, server.password, None);
            assert_refused(&server, settings, echo, "no matching auth method").await;
            eprintln!("missing credentials refused");
        }
    })
    .await
    .unwrap();
}
