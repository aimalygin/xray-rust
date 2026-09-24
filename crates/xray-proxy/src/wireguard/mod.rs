//! Configuration/cryptokey-routing primitives, not a WireGuard crypto engine.
//! Runtime integration must authenticate/decrypt before source-peer validation.
mod keys;
mod peers;

pub use keys::{KeyError, KeyMaterial};
pub use peers::{AllowedIp, PeerRoutes, RouteError, MAX_ALLOWED_IPS, MAX_PEERS};
