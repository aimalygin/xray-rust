//! Shared local oracle launcher. Tests only; private key material stays in Go.
use std::{
    io::{BufRead, BufReader},
    net::SocketAddr,
    process::{Child, Command, Stdio},
};

pub struct Oracle {
    child: Child,
    pub address: SocketAddr,
    pub encryption: String,
    pub tls_pin: String,
}

impl Oracle {
    pub fn start(mode: &str, kind: &str, flip: i32, application: &str) -> Self {
        let path = std::env::var_os("XRAY_VLESS_ENCRYPTION_ORACLE")
            .expect("run scripts/check-vless-encryption-oracle.sh");
        let mut child = Command::new(path)
            .args(["serve", mode, kind, &flip.to_string(), application])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start pinned Go oracle");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).expect("oracle startup");
        Self {
            child,
            address: value["address"].as_str().unwrap().parse().unwrap(),
            encryption: value["encryption"].as_str().unwrap().to_owned(),
            tls_pin: value["tlsPin"].as_str().unwrap().to_owned(),
        }
    }

    pub fn finish(mut self) {
        assert!(self.child.wait().unwrap().success(), "Go oracle failed");
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
