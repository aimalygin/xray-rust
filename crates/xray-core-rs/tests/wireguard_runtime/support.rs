#![allow(dead_code)]
use crate::hysteria_support as common;
#[path = "../../../xray-wireguard/tests/support/mod.rs"]
pub(crate) mod reference;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
pub use common::{echo, socks, tcp_echo, udp_echo, Protector};
use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_core_rs::Core;
use xray_transport::{DnsResolver, TransportDialer, TransportError};
pub const DEADLINE: Duration = Duration::from_secs(40);
pub const INNER_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
pub struct ReferenceServer {
    pub address: SocketAddr,
    preshared_key: Option<[u8; 32]>,
    _reference: reference::Reference,
}
impl ReferenceServer {
    pub async fn start() -> Self {
        Self::start_with_psk(None).await
    }
    pub async fn start_with_psk(preshared_key: Option<[u8; 32]>) -> Self {
        let reference = reference::Reference::start_with_psk(
            &StaticSecret::from([0x53; 32]),
            &PublicKey::from(&StaticSecret::from([0x42; 32])),
            preshared_key.as_ref(),
        )
        .await;
        Self {
            address: reference.address,
            preshared_key,
            _reference: reference,
        }
    }
}
pub fn profile(address: SocketAddr) -> Value {
    let mut profile: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/configs/wireguard.json"
    ))
    .unwrap();
    profile["inbounds"] = json!([
        {"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":0,"settings":{"auth":"noauth","udp":true}},
        {"tag":"http-in","protocol":"http","listen":"127.0.0.1","port":0},
        {"tag":"tun-in","protocol":"tun"}
    ]);
    profile["outbounds"][0]["settings"]["peers"][0]["publicKey"] =
        json!(STANDARD.encode(PublicKey::from(&StaticSecret::from([0x53; 32])).as_bytes()));
    profile["outbounds"][0]["settings"]["peers"][0]["endpoint"] =
        json!(format!("bootstrap.example:{}", address.port()));
    profile
}
#[derive(Default)]
pub struct Bootstrap(pub AtomicUsize);
#[async_trait]
impl DnsResolver for Bootstrap {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        assert_eq!(domain, "bootstrap.example");
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }
}
pub fn core(
    server: &ReferenceServer,
) -> (Core, Arc<Protector>, Arc<Bootstrap>, Arc<TransportDialer>) {
    let protector = Arc::new(Protector::default());
    let bootstrap = Arc::new(Bootstrap::default());
    let dialer = Arc::new(
        TransportDialer::system()
            .unwrap()
            .with_socket_protector(protector.clone()),
    );
    let mut profile = profile(server.address);
    if let Some(key) = server.preshared_key {
        profile["outbounds"][0]["settings"]["peers"][0]["preSharedKey"] =
            json!(STANDARD.encode(key));
    }
    let config = xray_config::parse_xray_json(&profile.to_string())
        .unwrap()
        .config;
    (
        Core::with_runtime_dependencies(config, bootstrap.clone(), dialer.clone()).unwrap(),
        protector,
        bootstrap,
        dialer,
    )
}
