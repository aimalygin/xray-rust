#![allow(dead_code)]
use crate::hysteria_support as common;
use common::server as tls;
pub use common::{echo, socks, tcp_echo, udp_echo, Bootstrap, Protector};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use xray_core_rs::Core;
use xray_transport::{TlsConnector, TransportDialer};
pub const PASSWORD: &str = "synthetic-local-trojan-test-password";
pub const DEADLINE: Duration = Duration::from_secs(20);

pub fn independent_reference() -> bool {
    match std::env::var("XRAY_CLIENT_PROTOCOL_REFERENCE").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("xray") => false,
        Ok("sing-box") => true,
        _ => panic!("unknown client protocol reference"),
    }
}

pub fn reference_supports(protocol: &str, network: &str) -> bool {
    !independent_reference()
        || (network != "xhttp" && (protocol != "shadowsocks" || network == "raw"))
}

pub struct ReferenceServer {
    child: Child,
    directory: PathBuf,
    pub address: SocketAddr,
    pub connector: TlsConnector,
    pub stream: Value,
    protocol: &'static str,
    settings: Value,
}
impl ReferenceServer {
    pub async fn start(network: &str) -> Self {
        Self::start_protocol(network, None, None).await
    }
    pub async fn start_shadowsocks(network: &str, method: &str, identity: bool) -> Self {
        Self::start_protocol(network, Some((method, identity)), None).await
    }
    pub async fn start_vmess(network: &str, cipher: &str, experiments: &str) -> Self {
        Self::start_protocol(network, None, Some((cipher, experiments))).await
    }
    async fn start_protocol(
        network: &str,
        shadowsocks: Option<(&str, bool)>,
        vmess: Option<(&str, &str)>,
    ) -> Self {
        let independent = independent_reference();
        assert!(reference_supports(
            if shadowsocks.is_some() {
                "shadowsocks"
            } else {
                "vmess"
            },
            network
        ));
        let binary =
            std::env::var_os("XRAY_CLIENT_PROTOCOL_BINARY").expect("run check-trojan-interop.sh");
        let directory = std::env::temp_dir().join(format!(
            "xray-trojan-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let identity = tls::identity();
        std::fs::write(directory.join("cert.pem"), identity.cert_pem).unwrap();
        std::fs::write(directory.join("key.pem"), identity.key_pem).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut stream = json!({"network":network,"security":"tls","tlsSettings":{"serverName":"localhost","alpn":[if matches!(network,"grpc"|"xhttp") {"h2"} else {"http/1.1"}]}});
        match network {
            "ws" => stream["wsSettings"] = json!({"path":"/trojan"}),
            "httpupgrade" => stream["httpupgradeSettings"] = json!({"path":"/trojan"}),
            "grpc" => stream["grpcSettings"] = json!({"serviceName":"trojan"}),
            "xhttp" => {
                stream["xhttpSettings"] =
                    json!({"path":"/trojan","mode":"stream-one","xmux":{"maxConnections":1}})
            }
            "raw" => {}
            _ => panic!("unknown carrier"),
        }
        if (shadowsocks.is_some() || vmess.is_some()) && network == "raw" {
            stream = json!({"network":"raw"});
        }
        let (protocol, settings, server_settings) = if let Some((cipher, experiments)) = vmess {
            let id = "00112233-4455-6677-8899-aabbccddeeff";
            (
                "vmess",
                json!({"address":"bootstrap.example","port":address.port(),"id":id,"security":cipher,"experiments":experiments}),
                json!({"clients":[{"id":id}]}),
            )
        } else if let Some((method, identity)) = shadowsocks {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let size = if method.contains("128") { 16 } else { 32 };
            let first = STANDARD.encode(vec![1; size]);
            let user = STANDARD.encode(vec![2; size]);
            let password = if identity {
                format!("{first}:{user}")
            } else {
                first.clone()
            };
            let mut server = json!({"method":method,"password":first,"network":"tcp,udp"});
            if identity {
                server["clients"] = json!([{"password":user,"email":"synthetic-user"}]);
            }
            (
                "shadowsocks",
                json!({"address":"bootstrap.example","port":address.port(),"method":method,"password":password}),
                server,
            )
        } else {
            (
                "trojan",
                json!({"address":"bootstrap.example","port":address.port(),"password":PASSWORD}),
                json!({"clients":[{"password":PASSWORD}]}),
            )
        };
        // A pinned test connector deliberately ignores per-outbound TLS shape.
        // Set its ALPN explicitly while retaining the generated test root.
        let mut client_tls = (*identity
            .connector
            .client_config_for(&tls::tls_settings())
            .unwrap())
        .clone();
        client_tls.alpn_protocols = if matches!(network, "grpc" | "xhttp") {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let connector = TlsConnector::with_pinned_client_config(Arc::new(client_tls));
        let mut server_stream = stream.clone();
        server_stream["tlsSettings"]["certificates"] = json!([{"certificateFile":directory.join("cert.pem"),"keyFile":directory.join("key.pem")}]);
        let config = if independent {
            let mut inbound =
                json!({"type":protocol,"listen":"127.0.0.1","listen_port":address.port()});
            match protocol {
                "trojan" => {
                    inbound["users"] = json!([{"name":"synthetic-user","password":PASSWORD}])
                }
                "vmess" => {
                    inbound["users"] = json!([{"name":"synthetic-user","uuid":settings["id"]}])
                }
                "shadowsocks" => {
                    inbound["method"] = server_settings["method"].clone();
                    inbound["password"] = server_settings["password"].clone();
                    if let Some(users) = server_settings["clients"].as_array() {
                        inbound["users"] = json!(users
                            .iter()
                            .map(|user| json!({"name":user["email"],"password":user["password"]}))
                            .collect::<Vec<_>>());
                    }
                }
                _ => unreachable!(),
            }
            if stream["security"] == "tls" {
                inbound["tls"] = json!({"enabled":true,"server_name":"localhost","alpn":stream["tlsSettings"]["alpn"],"certificate_path":directory.join("cert.pem"),"key_path":directory.join("key.pem")});
            }
            match network {
                "raw" => {}
                "ws" | "httpupgrade" => {
                    inbound["transport"] = json!({"type":network,"path":"/trojan"})
                }
                "grpc" => inbound["transport"] = json!({"type":"grpc","service_name":"trojan"}),
                _ => unreachable!(),
            }
            json!({"log":{"level":"debug","disabled":false},"inbounds":[inbound],"outbounds":[{"type":"direct","tag":"direct"}]})
        } else {
            json!({"log":{"loglevel":"debug"},"inbounds":[{"listen":"127.0.0.1","port":address.port(),"protocol":protocol,"settings":server_settings,"streamSettings":server_stream}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8","::1/128"]}]}}]})
        };
        std::fs::write(
            directory.join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        drop(listener);
        let log = std::fs::File::create(directory.join("server.log")).unwrap();
        let child = Command::new(binary)
            .args(["run", if independent { "-c" } else { "-config" }])
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
            connector,
            stream,
            protocol,
            settings,
        };
        server.wait_ready().await;
        server
    }
    pub async fn restart(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        let log = std::fs::File::create(self.directory.join("server.log")).unwrap();
        self.child = Command::new(std::env::var_os("XRAY_CLIENT_PROTOCOL_BINARY").unwrap())
            .args([
                "run",
                if independent_reference() {
                    "-c"
                } else {
                    "-config"
                },
            ])
            .arg(self.directory.join("config.json"))
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.wait_ready().await;
    }
    async fn wait_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            assert!(self.child.try_wait().unwrap().is_none(), "reference exited");
            if std::fs::read_to_string(self.directory.join("server.log"))
                .unwrap()
                .contains(if independent_reference() {
                    "sing-box started ("
                } else {
                    "core: Xray 26.7.28 started"
                })
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "reference startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    pub fn profile(&self) -> Value {
        json!({"inbounds":[
            {"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":0,"settings":{"udp":true}},
            {"tag":"http-in","protocol":"http","listen":"127.0.0.1","port":0},
            {"tag":"tun-in","protocol":"tun"}],
            "outbounds":[{"tag":"proxy","protocol":self.protocol,"settings":self.settings,"streamSettings":self.stream}]})
    }
    pub fn core(&self) -> (Core, Arc<Protector>, Arc<Bootstrap>, Arc<TransportDialer>) {
        let protector = Arc::new(Protector::default());
        let bootstrap = Arc::new(Bootstrap::default());
        let dialer = Arc::new(
            TransportDialer::with_tls_connector(self.connector.clone())
                .with_socket_protector(protector.clone()),
        );
        let config = xray_config::parse_xray_json(&self.profile().to_string())
            .unwrap()
            .config;
        (
            Core::with_runtime_dependencies(config, bootstrap.clone(), dialer.clone()).unwrap(),
            protector,
            bootstrap,
            dialer,
        )
    }
}
impl Drop for ReferenceServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "local protocol reference log:\n{}",
                std::fs::read_to_string(self.directory.join("server.log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
