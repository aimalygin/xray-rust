//! WireGuard client transport and an independently bounded userspace IP interface.
// Arguments are not evaluated, and no trace storage exists, without the feature.
macro_rules! diagnostic {
    ($stop:expr, $event:expr, $a:expr, $b:expr, $c:expr) => {
        #[cfg(feature = "diagnostics")]
        $stop
            .diagnostic
            .record($event, $a as u64, $b as u64, $c as u64);
    };
}
mod client;
mod config;
#[cfg(feature = "diagnostics")]
mod diagnostics;
mod io;
mod stack;

pub use client::{Client, Error, TcpStream, UdpSession};
pub use config::{Config, PeerConfig};
