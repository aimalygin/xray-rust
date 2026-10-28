#![allow(dead_code)]
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

pub const DEADLINE: Duration = Duration::from_secs(20);
pub const USER: &str = "synthetic-socks-user";
pub const PASS: &str = "synthetic-socks-pass";
pub const REMOTE_DOMAIN: &str = "echo.socks-interop.test";

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
        Self::start_with_options(false, None).await
    }

    pub async fn start_tls() -> Self {
        Self::start_with_options(true, None).await
    }

    pub async fn forwarding(outbound: Value) -> Self {
        Self::start_with_options(false, Some(outbound)).await
    }

    async fn start_with_options(tls: bool, outbound: Option<Value>) -> Self {
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
        let mut config = json!({
            "log": {"loglevel": "debug"},
            "dns": {"hosts": {REMOTE_DOMAIN: "127.0.0.1"}},
            "inbounds": [
                {"listen": "127.0.0.1", "port": password, "protocol": "socks",
                 "settings": {"auth": "password", "udp": true, "accounts": [{"user": USER, "pass": PASS}]}},
                {"listen": "127.0.0.1", "port": noauth, "protocol": "socks",
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
        let mut server = Self {
            child,
            directory,
            password,
            noauth,
            connector,
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
