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
    pub acceptor: tokio_rustls::TlsAcceptor,
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
    // A server that would pick HTTP/2 if the client offered it.
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
    // separately verify that the HTTP policy forces an HTTP/1.1-only offer.
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsIdentity {
        trusted_connector: xray_transport::TlsConnector::with_pinned_client_config(Arc::new(
            client,
        )),
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        pin: Sha256::digest(&der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        cert_pem: pem("CERTIFICATE", &der),
        key_pem: pem("PRIVATE KEY", &key),
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

/// One received request head and the ALPN protocol its TLS session agreed.
#[derive(Clone, Debug)]
pub struct Captured {
    pub head: String,
    pub alpn: Option<Vec<u8>>,
}

/// A minimal HTTP CONNECT proxy, plain or over TLS. It reads the head one
/// byte at a time, so nothing after it is consumed, and maps `REMOTE_DOMAIN`
/// to `remote` so domain targets are resolved here and nowhere else.
pub struct ScriptedProxy {
    pub address: SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
    task: tokio::task::JoinHandle<()>,
}

impl ScriptedProxy {
    pub async fn start(
        reply: Reply,
        tls: Option<tokio_rustls::TlsAcceptor>,
        remote: IpAddr,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let log = captured.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (tls, log) = (tls.clone(), log.clone());
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                            serve(stream, alpn, reply, remote, log).await;
                        }
                        None => serve(stream, None, reply, remote, log).await,
                    }
                });
            }
        });
        Self {
            address,
            captured,
            task,
        }
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
    log.lock().unwrap().push(Captured { head, alpn });
    match reply {
        Reply::Status(status) => {
            let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(response.as_bytes()).await;
        }
        Reply::Tunnel(early) => {
            let (host, port) = authority.rsplit_once(':').unwrap();
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let ip = match host.parse() {
                Ok(ip) => ip,
                Err(_) if host == REMOTE_DOMAIN => remote,
                Err(_) => panic!("unexpected CONNECT host {host}"),
            };
            let mut upstream = TcpStream::connect((ip, port.parse().unwrap()))
                .await
                .unwrap();
            let response = [b"HTTP/1.1 200 Connection established\r\n\r\n", early].concat();
            stream.write_all(&response).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
    }
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
                inbound["streamSettings"] = json!({"network":"raw", "security":"tls", "tlsSettings": {
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
            if self.log().contains("core: Xray 26.10.21 started") {
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
