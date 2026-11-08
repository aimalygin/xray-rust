//! WireGuard client transport and an independently bounded userspace IP interface.
mod client;
mod config;
mod io;
mod netstack;
mod stack;

pub use client::{Client, Error, TcpStream, UdpSession};
pub use config::{Config, PeerConfig};
pub use netstack::{Netstack, NetstackPackets};
