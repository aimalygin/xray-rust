// This helper is shared by focused mock tests and the optional full Xray suite.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use xray_transport::hysteria::HysteriaConfig;
use xray_transport::{TlsClientConfig, TlsConnector};

pub const AUTH: &str = "synthetic-local-hysteria-test-auth";
pub const DEADLINE: Duration = Duration::from_secs(8);

pub fn tls_settings() -> TlsClientConfig {
    TlsClientConfig {
        server_name: "localhost".into(),
        allow_insecure: false,
        pinned_peer_cert_sha256: vec![],
        verify_peer_cert_by_name: vec![],
        alpn: vec![],
        fingerprint: None,
    }
}

pub struct Identity {
    pub connector: TlsConnector,
    pub server: quinn::ServerConfig,
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn identity() -> Identity {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.cert.der().clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Identity {
        connector: TlsConnector::with_pinned_client_config(Arc::new(client)),
        server,
        cert_pem: pem("CERTIFICATE", cert.cert.der()),
        key_pem: pem("PRIVATE KEY", &cert.signing_key.serialize_der()),
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

pub struct XrayServer {
    child: Child,
    pub directory: PathBuf,
    pub address: SocketAddr,
    pub connector: TlsConnector,
}

impl XrayServer {
    pub async fn start() -> Self {
        let binary = std::env::var_os("XRAY_HYSTERIA_BINARY")
            .expect("run scripts/check-hysteria-interop.sh to build the pinned Xray binary");
        let directory = std::env::temp_dir().join(format!(
            "xray-hysteria-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity = identity();
        std::fs::write(directory.join("cert.pem"), identity.cert_pem).unwrap();
        std::fs::write(directory.join("key.pem"), identity.key_pem).unwrap();
        let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = reservation.local_addr().unwrap();
        let config = serde_json::json!({"log":{"loglevel":"debug"},
            "inbounds":[{"listen":"127.0.0.1","port":address.port(),"protocol":"hysteria",
                "settings":{"version":2,"users":[{"auth":AUTH}]},
                "streamSettings":{"network":"hysteria","security":"tls", "hysteriaSettings":{"version":2},
                    "tlsSettings":{"alpn":["h3"],"certificates":[{"certificateFile":directory.join("cert.pem"),"keyFile":directory.join("key.pem")}]} }}],
            // Pinned Xray blocks private destinations for Hysteria by default.
            // These synthetic echo fixtures explicitly permit loopback only.
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]});
        std::fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        drop(reservation);
        let log = std::fs::File::create(directory.join("server.log")).unwrap();
        let child = Command::new(binary)
            .arg("run")
            .arg("-config")
            .arg(directory.join("config.json"))
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            directory,
            address,
            connector: identity.connector,
        };
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "Xray exited at startup"
            );
            if std::fs::read_to_string(server.directory.join("server.log"))
                .unwrap()
                .contains("core: Xray 26.7.28 started")
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Xray startup deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        server
    }

    pub fn config(&self) -> HysteriaConfig {
        HysteriaConfig::new(self.address, tls_settings(), AUTH.into())
    }
}

impl Drop for XrayServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "local Xray test log:\n{}",
                std::fs::read_to_string(self.directory.join("server.log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub fn localhost() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

pub struct Task(pub tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
