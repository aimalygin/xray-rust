pub mod hysteria;
pub mod inbound;
pub mod vless;
pub mod wireguard;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
