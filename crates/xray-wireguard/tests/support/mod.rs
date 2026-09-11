#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::time::{sleep, timeout};
use x25519_dalek::{PublicKey, StaticSecret};
const WAIT: Duration = Duration::from_secs(5);
pub struct Reference {
    child: Child,
    pub directory: PathBuf,
    pub address: SocketAddr,
}
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "{}",
                std::fs::read_to_string(self.directory.join("log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Reference {
    pub async fn start(server_secret: &StaticSecret, client_public: &PublicKey) -> Self {
        Self::start_with_psk(server_secret, client_public, None).await
    }
    pub async fn start_with_psk(
        server_secret: &StaticSecret,
        client_public: &PublicKey,
        preshared_key: Option<&[u8; 32]>,
    ) -> Self {
        Self::start_custom(
            server_secret,
            client_public,
            preshared_key,
            Ipv4Addr::LOCALHOST.into(),
            0,
        )
        .await
    }
    pub async fn start_custom(
        server_secret: &StaticSecret,
        client_public: &PublicKey,
        preshared_key: Option<&[u8; 32]>,
        listen: IpAddr,
        redirect_port: u16,
    ) -> Self {
        Self::start_inner(
            server_secret,
            client_public,
            preshared_key,
            listen,
            redirect_port,
            false,
        )
        .await
    }

    pub async fn start_raw(
        server_secret: &StaticSecret,
        client_public: &PublicKey,
        preshared_key: &[u8; 32],
        listen: IpAddr,
    ) -> Self {
        Self::start_inner(
            server_secret,
            client_public,
            Some(preshared_key),
            listen,
            0,
            true,
        )
        .await
    }

    async fn start_inner(
        server_secret: &StaticSecret,
        client_public: &PublicKey,
        preshared_key: Option<&[u8; 32]>,
        listen: IpAddr,
        redirect_port: u16,
        raw: bool,
    ) -> Self {
        let (binary, native) = match (
            std::env::var_os("XRAY_WIREGUARD_BINARY"),
            std::env::var_os("NATIVE_WIREGUARD_BINARY"),
        ) {
            (Some(binary), None) => (binary, false),
            (None, Some(binary)) => (binary, true),
            _ => panic!("select exactly one reference with check-wireguard-runtime.sh or check-native-wireguard-interop.sh"),
        };
        assert!(
            !raw || native,
            "raw packet bridge requires native wireguard-go"
        );
        // Darwin's per-user temporary path can exceed sockaddr_un's path limit.
        let root = if raw {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let directory = root.join(format!(
            "xray-wg-probe-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let reservation = std::net::UdpSocket::bind((listen, 0)).unwrap();
        let address = reservation.local_addr().unwrap();
        // All keys are synthetic public test vectors. Xray gVisor rejects inner
        // loopback destinations, so use a documentation IP and redirect to the
        // local echo server. No packet is sent to the documentation address.
        let config = format!(
            r#"{{"log":{{"loglevel":"debug"}},"inbounds":[{{"listen":"127.0.0.1","port":{},"protocol":"wireguard","settings":{{"secretKey":"{}","address":["10.44.0.1/32","fd44::1/128"],"mtu":1420,"peers":[{{"publicKey":"{}","allowedIPs":["10.44.0.2/32","fd44::2/128"]}}]}}}}],"outbounds":[{{"protocol":"freedom","settings":{{"redirect":"127.0.0.1:0","finalRules":[{{"action":"allow","ip":["127.0.0.0/8"]}}]}}}}]}}"#,
            address.port(),
            STANDARD.encode(server_secret.to_bytes()),
            STANDARD.encode(client_public.as_bytes())
        );
        let mut config: serde_json::Value = serde_json::from_str(&config).unwrap();
        config["inbounds"][0]["listen"] = serde_json::json!(listen.to_string());
        config["outbounds"][0]["settings"]["redirect"] =
            serde_json::json!(format!("127.0.0.1:{redirect_port}"));
        if let Some(key) = preshared_key {
            config["inbounds"][0]["settings"]["peers"][0]["preSharedKey"] =
                serde_json::json!(STANDARD.encode(key));
        }
        if native {
            fn hex(bytes: &[u8]) -> String {
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            }
            config = serde_json::json!({
                "listen": address.to_string(),
                "privateKey": hex(&server_secret.to_bytes()),
                "peerKey": hex(client_public.as_bytes()),
                "presharedKey": preshared_key.map(|key| hex(key)).unwrap_or_default(),
                "redirectPort": redirect_port,
            });
            if raw {
                config["packetSocket"] = serde_json::json!(directory.join("server.sock"));
                config["packetClient"] = serde_json::json!(directory.join("client.sock"));
            }
        }
        std::fs::write(directory.join("config.json"), config.to_string()).unwrap();
        drop(reservation);
        let log = std::fs::File::create(directory.join("log")).unwrap();
        let mut command = Command::new(binary);
        let startup = if native {
            "wireguard-go reference ready"
        } else {
            command.args(["run", "-config"]);
            "core: Xray 26.7.28 started"
        };
        let child = command
            .arg(directory.join("config.json"))
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut reference = Self {
            child,
            directory,
            address,
        };
        timeout(WAIT, async {
            loop {
                assert!(
                    reference.child.try_wait().unwrap().is_none(),
                    "reference exited"
                );
                if std::fs::read_to_string(reference.directory.join("log"))
                    .unwrap()
                    .contains(startup)
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        reference
    }
}
