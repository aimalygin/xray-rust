#![allow(dead_code)]
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

pub const DEADLINE: Duration = Duration::from_secs(20);
pub const USER: &str = "synthetic-socks-user";
pub const PASS: &str = "synthetic-socks-pass";
pub const REMOTE_DOMAIN: &str = "echo.socks-interop.test";
/// Starts of Xray whose port another socket took, each on fresh ports. The
/// harness picks both ports by binding them and lets go for Xray to bind; a
/// parallel test's socket can take one in between ("address already in
/// use"). Only the TCP listen races: Xray 26.11.9's SOCKS inbound binds no
/// UDP socket at startup, `udp` on or not.
const PORT_ATTEMPTS: usize = 5;

/// Pinned Xray with a password inbound and a no-auth inbound on loopback.
pub struct XrayServer {
    child: Child,
    directory: PathBuf,
    pub password: u16,
    pub noauth: u16,
    pub connector: Option<xray_transport::TlsConnector>,
}

impl XrayServer {
    pub async fn start() -> Self {
        Self::start_on(Ipv4Addr::LOCALHOST.into(), false).await
    }

    pub async fn start_tls() -> Self {
        Self::start_on(Ipv4Addr::LOCALHOST.into(), true).await
    }

    pub async fn start_on(listen: IpAddr, tls: bool) -> Self {
        Self::start_with_options(listen, tls, None).await
    }

    pub async fn forwarding(outbound: Value) -> Self {
        Self::start_with_options(Ipv4Addr::LOCALHOST.into(), false, Some(outbound)).await
    }

    async fn start_with_options(listen: IpAddr, tls: bool, outbound: Option<Value>) -> Self {
        for attempt in 1..=PORT_ATTEMPTS {
            let mut server = Self::spawn(listen, tls, outbound.clone());
            if server.wait_ready().await {
                return server;
            }
            assert!(
                attempt < PORT_ATTEMPTS,
                "Xray's ports were taken on all {PORT_ATTEMPTS} starts"
            );
            eprintln!(
                "Xray lost port {} or {} to another socket; starting it again on fresh \
                 ports ({attempt} of {PORT_ATTEMPTS})",
                server.password, server.noauth
            );
        }
        unreachable!("the last start returns or panics")
    }

    /// Writes a config on fresh ports and spawns Xray with it.
    fn spawn(listen: IpAddr, tls: bool, outbound: Option<Value>) -> Self {
        let binary = std::env::var_os("XRAY_CLIENT_PROTOCOL_BINARY")
            .expect("run scripts/check-socks-interop.sh");
        let directory = std::env::temp_dir().join(format!(
            "xray-socks-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        // Hold both listeners until the config is written so the ports differ.
        let listeners = [(); 2].map(|_| std::net::TcpListener::bind((listen, 0)).unwrap());
        let [password, noauth] = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap().port());
        let mut config = json!({
            "log": {"loglevel": "debug"},
            "dns": {"hosts": {REMOTE_DOMAIN: "127.0.0.1"}},
            "inbounds": [
                {"listen": listen.to_string(), "port": password, "protocol": "socks",
                 "settings": {"auth": "password", "udp": true, "accounts": [{"user": USER, "pass": PASS}]}},
                {"listen": listen.to_string(), "port": noauth, "protocol": "socks",
                 "settings": {"auth": "noauth", "udp": true}}
            ],
            "outbounds": [{"protocol": "freedom", "settings": {
                "domainStrategy": "UseIPv4",
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8", "::1/128"]}]
            }}]
        });
        if let Some(outbound) = outbound {
            config["outbounds"] = json!([outbound]);
        }
        let connector = tls.then(|| {
            let identity = crate::hysteria_support::server::identity();
            std::fs::write(directory.join("cert.pem"), identity.cert_pem).unwrap();
            std::fs::write(directory.join("key.pem"), identity.key_pem).unwrap();
            for inbound in config["inbounds"].as_array_mut().unwrap() {
                inbound["streamSettings"] = json!({"network":"raw", "security":"tls", "tlsSettings": {
                    "certificates":[{"certificateFile":directory.join("cert.pem"),"keyFile":directory.join("key.pem")}]
                }});
            }
            identity.connector
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
        Self {
            child,
            directory,
            password,
            noauth,
            connector,
        }
    }

    /// Waits for Xray's startup record: `false` when Xray exited because
    /// another socket held one of its ports, a panic when it exited for
    /// anything else.
    async fn wait_ready(&mut self) -> bool {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            if self.child.try_wait().unwrap().is_some() {
                assert!(self.lost_port(), "Xray exited");
                return false;
            }
            if self.log().contains("core: Xray 26.11.9 started") {
                return true;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Xray startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Whether Xray's log says another socket held one of its ports, as Go
    /// words a failed listen: `listen tcp 127.0.0.1:37655: bind: address
    /// already in use`.
    fn lost_port(&self) -> bool {
        let log = self.log();
        [self.password, self.noauth]
            .iter()
            .any(|port| log.contains(&format!(":{port}: bind: address already in use")))
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
    outbound_settings_at(form, "bootstrap.example", port, account)
}

pub fn outbound_settings_at(
    form: Form,
    address: &str,
    port: u16,
    account: Option<(&str, &str)>,
) -> Value {
    match (form, account) {
        (Form::Flat, None) => json!({"address": address, "port": port}),
        (Form::Flat, Some((user, pass))) => {
            json!({"address": address, "port": port, "user": user, "pass": pass})
        }
        (Form::Servers, None) => {
            json!({"servers": [{"address": address, "port": port}]})
        }
        (Form::Servers, Some((user, pass))) => json!({"servers": [{
            "address": address, "port": port,
            "users": [{"user": user, "pass": pass}]
        }]}),
    }
}

pub fn profile(settings: Value, tls: bool) -> Value {
    let mut profile = json!({
        "inbounds": [
            {"tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,
             "settings":{"auth":"noauth", "udp":true}},
            {"tag":"tun-in", "protocol":"tun"}
        ],
        "outbounds":[{"tag":"proxy", "protocol":"socks", "settings":settings}]
    });
    if tls {
        profile["outbounds"][0]["streamSettings"] = json!({
            "network":"raw", "security":"tls", "tlsSettings":{"serverName":"localhost"}
        });
    }
    profile
}
