#![allow(dead_code)]
use base64::Engine as _;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub const DEADLINE: Duration = Duration::from_secs(20);
pub const USER: &str = "synthetic-http-user";
pub const PASS: &str = "synthetic-http-pass";
pub const REMOTE_DOMAIN: &str = "echo.http-interop.test";

/// A self-signed `localhost` certificate: an acceptor that prefers `h2`, and
/// the PEM files and SHA-256 pin a client or Xray needs.
pub struct TlsIdentity {
    /// Picks HTTP/2 when the client offers it.
    pub acceptor: tokio_rustls::TlsAcceptor,
    /// Offers HTTP/1.1 alone.
    pub http11_acceptor: tokio_rustls::TlsAcceptor,
    server_config: rustls::ServerConfig,
    pub pin: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub trusted_connector: xray_transport::TlsConnector,
}

pub fn tls_identity() -> TlsIdentity {
    tls_identity_for(vec!["localhost".into()])
}

pub fn tls_identity_for(names: Vec<String>) -> TlsIdentity {
    let cert = rcgen::generate_simple_self_signed(names).unwrap();
    let der = cert.cert.der().clone();
    let key = cert.signing_key.serialize_der();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![der.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())),
    )
    .unwrap();
    let server_config = config.clone();
    let mut http11 = config.clone();
    http11.alpn_protocols = vec![b"http/1.1".to_vec()];
    // A server that picks HTTP/2 when the client offers it.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    // This test-only connector pins the complete config, including ALPN.
    // Trust/name checks remain active; the system-connector runtime tests
    // separately cover what the HTTP outbound's own TLS offers.
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsIdentity {
        trusted_connector: xray_transport::TlsConnector::with_pinned_client_config(Arc::new(
            client,
        )),
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        http11_acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(http11)),
        server_config,
        pin: Sha256::digest(&der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        cert_pem: pem("CERTIFICATE", &der),
        key_pem: pem("PRIVATE KEY", &key),
    }
}

impl TlsIdentity {
    /// An acceptor that offers `protocols` alone.
    pub fn acceptor_offering(&self, protocols: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
        let mut config = self.server_config.clone();
        config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// How [`ScriptedProxy`] answers every CONNECT.
#[derive(Clone, Copy, Debug)]
pub enum Reply {
    /// 200 followed by these bytes in the same write, then a tunnel to the
    /// requested authority.
    Tunnel(&'static [u8]),
    /// This status line (without `HTTP/1.1 `) and nothing else.
    Status(&'static str),
}

/// One received CONNECT and the ALPN protocol its TLS session agreed.
#[derive(Clone, Debug)]
pub struct Captured {
    /// The HTTP/1.1 head, or `CONNECT <authority> HTTP/2` for HTTP/2.
    pub head: String,
    pub alpn: Option<Vec<u8>>,
    /// The HTTP/2 request's fields in order; empty for HTTP/1.1.
    pub fields: Vec<(String, String)>,
    /// Which accepted connection, counted from 0, carried the request.
    pub connection: usize,
}

/// A minimal HTTP CONNECT proxy, plain or over TLS. It reads the head one
/// byte at a time, so nothing after it is consumed, and maps `REMOTE_DOMAIN`
/// to `remote` so domain targets are resolved here and nowhere else.
pub struct ScriptedProxy {
    pub address: SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
    /// HTTP/2 connections whose client went away.
    http2_ended: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

/// How [`ScriptedProxy`] serves HTTP/2 connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct Http2Options {
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub max_streams: Option<u32>,
    /// Send GOAWAY once this many requests arrived on a connection, and keep
    /// serving them.
    pub goaway_after: Option<usize>,
}

impl ScriptedProxy {
    pub async fn start(
        reply: Reply,
        tls: Option<tokio_rustls::TlsAcceptor>,
        remote: IpAddr,
    ) -> Self {
        Self::start_http2(reply, tls, remote, Http2Options::default()).await
    }

    pub async fn start_http2(
        reply: Reply,
        tls: Option<tokio_rustls::TlsAcceptor>,
        remote: IpAddr,
        options: Http2Options,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let log = captured.clone();
        let http2_ended = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ended = http2_ended.clone();
        let task = tokio::spawn(async move {
            for connection in 0.. {
                let (stream, _) = listener.accept().await.unwrap();
                let (tls, log, ended) = (tls.clone(), log.clone(), ended.clone());
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                            if alpn.as_deref() == Some(b"h2") {
                                serve_h2(stream, connection, reply, remote, options, log).await;
                                ended.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            } else {
                                serve(stream, alpn, connection, reply, remote, log).await;
                            }
                        }
                        None => serve(stream, None, connection, reply, remote, log).await,
                    }
                });
            }
        });
        Self {
            address,
            captured,
            http2_ended,
            task,
        }
    }

    /// A plain proxy behind an HTTPUpgrade transport on `path`: each
    /// connection is upgraded first, then serves one CONNECT as [`Self::start`]
    /// does.
    pub async fn start_behind_upgrade(reply: Reply, remote: IpAddr, path: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let log = captured.clone();
        let task = tokio::spawn(async move {
            for connection in 0.. {
                let (mut stream, _) = listener.accept().await.unwrap();
                let log = log.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = stream.read_u8().await else {
                            return;
                        };
                        head.push(byte);
                    }
                    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                    if !head.starts_with(&format!("get {path} http/1.1\r\n"))
                        || !head.contains("\r\nupgrade: websocket\r\n")
                    {
                        return;
                    }
                    let switched = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
                    stream.write_all(switched).await.unwrap();
                    serve(stream, None, connection, reply, remote, log).await;
                });
            }
        });
        Self {
            address,
            captured,
            http2_ended: Arc::default(),
            task,
        }
    }

    /// How many HTTP/2 connections their client has closed so far.
    pub fn http2_ended(&self) -> usize {
        self.http2_ended.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn captured(&self) -> Vec<Captured> {
        self.captured.lock().unwrap().clone()
    }
}

impl Drop for ScriptedProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve<S>(
    mut stream: S,
    alpn: Option<Vec<u8>>,
    connection: usize,
    reply: Reply,
    remote: IpAddr,
    log: Arc<Mutex<Vec<Captured>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let Ok(byte) = stream.read_u8().await else {
            return;
        };
        head.push(byte);
    }
    let head = String::from_utf8(head).unwrap();
    let authority = head.split(' ').nth(1).unwrap().to_owned();
    log.lock().unwrap().push(Captured {
        head,
        alpn,
        fields: Vec::new(),
        connection,
    });
    match reply {
        Reply::Status(status) => {
            let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(response.as_bytes()).await;
        }
        Reply::Tunnel(early) => {
            let mut upstream = connect_upstream(&authority, remote).await;
            let response = [b"HTTP/1.1 200 Connection established\r\n\r\n", early].concat();
            stream.write_all(&response).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
    }
}

/// Connects to a CONNECT authority, mapping `REMOTE_DOMAIN` to `remote`.
async fn connect_upstream(authority: &str, remote: IpAddr) -> TcpStream {
    let (host, port) = authority.rsplit_once(':').unwrap();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip = match host.parse() {
        Ok(ip) => ip,
        Err(_) if host == REMOTE_DOMAIN => remote,
        Err(_) => panic!("unexpected CONNECT host {host}"),
    };
    TcpStream::connect((ip, port.parse().unwrap()))
        .await
        .unwrap()
}

/// Serves CONNECT over HTTP/2: every request on the connection is logged
/// and answered as `reply` says, each tunnel on its own stream.
async fn serve_h2<S>(
    stream: S,
    connection: usize,
    reply: Reply,
    remote: IpAddr,
    options: Http2Options,
    log: Arc<Mutex<Vec<Captured>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    if let Some(max) = options.max_streams {
        builder.max_concurrent_streams(max);
    }
    let Ok(mut h2) = builder.handshake::<_, bytes::Bytes>(stream).await else {
        return;
    };
    let mut accepted = 0;
    while let Some(Ok((request, respond))) = h2.accept().await {
        accepted += 1;
        if options.goaway_after == Some(accepted) {
            h2.graceful_shutdown();
        }
        let authority = request.uri().authority().unwrap().to_string();
        log.lock().unwrap().push(Captured {
            head: format!("{} {authority} HTTP/2", request.method()),
            alpn: Some(b"h2".to_vec()),
            fields: request
                .headers()
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
                .collect(),
            connection,
        });
        tokio::spawn(answer_h2(request, respond, authority, reply, remote));
    }
}

async fn answer_h2(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    authority: String,
    reply: Reply,
    remote: IpAddr,
) {
    let early = match reply {
        Reply::Status(status) => {
            let code = status.split(' ').next().unwrap().parse::<u16>().unwrap();
            let response = http::Response::builder().status(code).body(()).unwrap();
            let _ = respond.send_response(response, true);
            return;
        }
        Reply::Tunnel(early) => early,
    };
    let upstream = connect_upstream(&authority, remote).await;
    let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
        return;
    };
    let mut recv = request.into_body();
    let (mut read, mut write) = upstream.into_split();
    let uplink = async move {
        while let Some(Ok(chunk)) = recv.data().await {
            if chunk.is_empty() {
                continue;
            }
            let _ = recv.flow_control().release_capacity(chunk.len());
            if write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    };
    let downlink = async move {
        let mut pending = bytes::Bytes::from_static(early);
        let mut buffer = vec![0; 16 * 1024];
        loop {
            while !pending.is_empty() {
                send.reserve_capacity(pending.len());
                match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(granted)) if granted > 0 => {
                        let chunk = pending.split_to(granted.min(pending.len()));
                        if send.send_data(chunk, false).is_err() {
                            return;
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return,
                }
            }
            match read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => pending = bytes::Bytes::copy_from_slice(&buffer[..read]),
            }
        }
        let _ = send.send_data(bytes::Bytes::new(), true);
    };
    tokio::join!(uplink, downlink);
}

/// The value of HTTP/2 field `name` in a capture.
pub fn field<'a>(captured: &'a Captured, name: &str) -> Option<&'a str> {
    captured
        .fields
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value.as_str()))
}

/// Header names of a request head in order, after the request line.
pub fn header_names(head: &str) -> Vec<&str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect()
}

/// The value of the first header named exactly `name`.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(": "))
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// Pinned Xray with an HTTP inbound that requires a synthetic Basic account
/// and an open one, both on loopback and forwarding to Freedom.
pub struct XrayServer {
    child: Child,
    directory: PathBuf,
    pub password: u16,
    pub noauth: u16,
    /// The SHA-256 pin of the TLS certificate, when the inbounds use TLS.
    pub pin: Option<String>,
    pub trusted_connector: Option<xray_transport::TlsConnector>,
}

impl XrayServer {
    pub async fn start() -> Self {
        Self::start_with_options(None, None).await
    }

    pub async fn start_tls() -> Self {
        Self::start_with_options(Some(tls_identity()), None).await
    }

    /// Replaces the outbounds, for a server whose inbounds feed an Xray client.
    pub async fn forwarding(outbound: Value) -> Self {
        Self::start_with_options(None, Some(outbound)).await
    }

    pub async fn start_tls_for_import() -> Self {
        Self::start_with_options(
            Some(tls_identity_for(vec![
                "bootstrap.example".into(),
                "127.0.0.1".into(),
            ])),
            None,
        )
        .await
    }

    async fn start_with_options(tls: Option<TlsIdentity>, outbound: Option<Value>) -> Self {
        let binary = std::env::var_os("XRAY_CLIENT_PROTOCOL_BINARY")
            .expect("run scripts/check-http-interop.sh");
        let directory = std::env::temp_dir().join(format!(
            "xray-http-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        // Hold both listeners until the config is written so the ports differ.
        let listeners = [(); 2].map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let [password, noauth] = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap().port());
        let mut config = json!({
            "log": {"loglevel": "debug"},
            "dns": {"hosts": {REMOTE_DOMAIN: "127.0.0.1"}},
            "inbounds": [
                {"listen": "127.0.0.1", "port": password, "protocol": "http",
                 "settings": {"accounts": [{"user": USER, "pass": PASS}]}},
                {"listen": "127.0.0.1", "port": noauth, "protocol": "http", "settings": {}}
            ],
            "outbounds": [{"protocol": "freedom", "settings": {
                "domainStrategy": "UseIPv4",
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8", "::1/128"]}]
            }}]
        });
        if let Some(outbound) = outbound {
            config["inbounds"][1] = json!({"listen": "127.0.0.1", "port": noauth,
                "protocol": "socks", "settings": {"auth": "noauth"}});
            config["outbounds"] = json!([outbound]);
        }
        let trusted_connector = tls
            .as_ref()
            .map(|identity| identity.trusted_connector.clone());
        let pin = tls.map(|identity| {
            std::fs::write(directory.join("cert.pem"), identity.cert_pem).unwrap();
            std::fs::write(directory.join("key.pem"), identity.key_pem).unwrap();
            for inbound in config["inbounds"].as_array_mut().unwrap() {
                // Xray-core's HTTP inbound reads HTTP/1.1 only, and its TLS
                // would pick h2 for any client that offers it, Xray-core's
                // own HTTP outbound included.
                inbound["streamSettings"] = json!({"network":"raw", "security":"tls", "tlsSettings": {
                    "alpn": ["http/1.1"],
                    "certificates":[{"certificateFile":directory.join("cert.pem"),"keyFile":directory.join("key.pem")}]
                }});
            }
            identity.pin
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
            pin,
            trusted_connector,
        };
        server.wait_ready().await;
        server
    }

    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            assert!(self.child.try_wait().unwrap().is_none(), "Xray exited");
            if self.log().contains("core: Xray 26.11.9 started") {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Xray startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn log(&self) -> String {
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
pub enum Form {
    Flat,
    Servers,
}

/// Outbound settings in either Xray form; the server name is resolved by
/// `Bootstrap`, which rejects every other name.
pub fn outbound_settings(form: Form, port: u16, account: Option<(&str, &str)>) -> Value {
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

/// `socks-in` routes everything to the `http` outbound tagged `proxy`.
/// `tls` is the certificate pin plus an optional uTLS fingerprint.
pub fn profile(settings: Value, tls: Option<(&str, Option<&str>)>) -> Value {
    let mut profile = json!({
        "inbounds": [
            {"tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,
             "settings":{"auth":"noauth", "udp":true}}
        ],
        "outbounds":[{"tag":"proxy", "protocol":"http", "settings":settings}]
    });
    if let Some((pin, fingerprint)) = tls {
        let mut tls_settings = json!({"serverName":"localhost", "pinnedPeerCertSha256": pin});
        if let Some(fingerprint) = fingerprint {
            tls_settings["fingerprint"] = json!(fingerprint);
        }
        profile["outbounds"][0]["streamSettings"] =
            json!({"network":"raw", "security":"tls", "tlsSettings": tls_settings});
    }
    profile
}
