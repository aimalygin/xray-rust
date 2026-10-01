mod aead;

pub mod hysteria;
pub mod inbound;
pub mod mux;
pub mod shadowsocks2022;
pub mod trojan;
pub mod vless;
pub mod vmess;
pub mod wireguard;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
