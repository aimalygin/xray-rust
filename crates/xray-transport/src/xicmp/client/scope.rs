//! The interface an xicmp socket leaves through on Apple systems.
//!
//! Inside a Network Extension the routes send everything into the tunnel,
//! and the system keeps the extension's own traffic out of it by scoping
//! its sockets to the physical interface: NECP's `SOCKET_SCOPED` result,
//! which XNU's `inp_update_necp_policy` applies as the socket's bound
//! interface. On an iPhone it scoped the extension's UDP sockets so but
//! left its ICMP datagram socket unbound: no echo request reached the
//! network until `sockopt.interface` bound the socket (the 0.10.0 device
//! campaign). XNU evaluates the same policies for ICMP sockets, so the ones
//! the system installs for the extension do not match them; nothing else
//! scopes such a socket (`rip_connect` records only the address,
//! `rip_output` routes as the socket is bound), and its echo requests
//! follow the tunnel's routes into the tunnel.
//!
//! So an ICMP socket the protector left unbound is bound here to the
//! interface the system gives a UDP socket of this process on its way to
//! the same address, and asks again while it sends, at most once a period:
//! it moves with the network as the UDP sockets opened after a change do,
//! and takes an interface once the system starts scoping, as when the dial
//! came before the tunnel's settings. Xray-core's server knows a client by
//! its id and answers where its latest request came from, so the connection
//! goes on over the new network.
//!
//! Where the system scopes no UDP socket, outside a Network Extension, the
//! ICMP socket stays unbound and follows the routes, as Xray-core's does. A
//! socket the protector bound, as `sockopt.interface` does, keeps its
//! interface and is not asked about again.
use crate::SocketProtector;
use std::{io, net::IpAddr, net::UdpSocket};

/// Whether a socket follows the interface the system scopes UDP sockets to,
/// and when it last asked.
#[derive(Debug)]
pub(super) struct Scope {
    #[cfg(target_vendor = "apple")]
    asked: Option<std::sync::Mutex<std::time::Instant>>,
}

impl Scope {
    /// Left as the protector made it.
    pub(super) const KEPT: Self = Self {
        #[cfg(target_vendor = "apple")]
        asked: None,
    };

    #[cfg(all(test, target_vendor = "apple"))]
    pub(super) fn follows(&self) -> bool {
        self.asked.is_some()
    }
}

#[cfg(target_vendor = "apple")]
mod apple {
    use super::*;
    use socket2::SockRef;
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        num::NonZeroU32,
        sync::Mutex,
        time::{Duration, Instant},
    };

    /// How long the system's answer stands before a send asks again. A
    /// question is a socket and three calls, sending nothing.
    pub(in super::super) const RECHECK: Duration = Duration::from_secs(1);
    /// Where the question's socket connects. Connecting a UDP socket needs
    /// a port; nothing goes to it.
    const PORT: u16 = 9;

    impl Scope {
        /// Binds `socket`, a fresh ICMP socket for `address` that the
        /// protector has seen, to the interface the system scopes UDP
        /// sockets to, unless the protector bound it. Where the system
        /// scopes none, or cannot route to `address`, the sends ask again.
        pub(in super::super) fn open(
            socket: &UdpSocket,
            address: IpAddr,
            protector: Option<&dyn SocketProtector>,
        ) -> io::Result<Self> {
            if bound(socket, address)?.is_some() {
                return Ok(Self::KEPT);
            }
            if let Ok(Some(index)) = system(address, protector) {
                bind(socket, address, index)?;
            }
            Ok(Self {
                asked: Some(Mutex::new(Instant::now())),
            })
        }

        /// Asks the system again once [`RECHECK`] has passed and moves
        /// `socket` to the interface it scopes UDP sockets to now. Where it
        /// scopes none, or cannot route, the socket stays as it is: a bound
        /// one unbound would send into the tunnel.
        pub(in super::super) fn refresh(
            &self,
            socket: &UdpSocket,
            address: IpAddr,
            protector: Option<&dyn SocketProtector>,
        ) {
            self.refresh_at(Instant::now(), socket, address, protector);
        }

        pub(in super::super) fn refresh_at(
            &self,
            now: Instant,
            socket: &UdpSocket,
            address: IpAddr,
            protector: Option<&dyn SocketProtector>,
        ) {
            let Some(asked) = &self.asked else {
                return;
            };
            // A sender asking now answers for the others.
            let Ok(mut asked) = asked.try_lock() else {
                return;
            };
            if now.saturating_duration_since(*asked) < RECHECK {
                return;
            }
            *asked = now;
            if let Ok(Some(index)) = system(address, protector) {
                if bound(socket, address).ok().flatten() != Some(index) {
                    // A failure leaves the socket where it was, to be
                    // asked about again.
                    let _ = bind(socket, address, index);
                }
            }
        }
    }

    /// The interface `socket` is bound to: `IP_BOUND_IF` or
    /// `IPV6_BOUND_IF`, which NECP's scoping sets as well.
    pub(in super::super) fn bound(
        socket: &UdpSocket,
        address: IpAddr,
    ) -> io::Result<Option<NonZeroU32>> {
        let socket = SockRef::from(socket);
        if address.is_ipv4() {
            socket.device_index_v4()
        } else {
            socket.device_index_v6()
        }
    }

    fn bind(socket: &UdpSocket, address: IpAddr, index: NonZeroU32) -> io::Result<()> {
        let socket = SockRef::from(socket);
        if address.is_ipv4() {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }

    /// The interface the system scopes a UDP socket of this process to on
    /// its way to `address`, if any: asked of one bound to the wildcard and
    /// protected, as the carriers' sockets are, then connected, which picks
    /// its route and sends nothing.
    pub(in super::super) fn system(
        address: IpAddr,
        protector: Option<&dyn SocketProtector>,
    ) -> io::Result<Option<NonZeroU32>> {
        let wildcard: SocketAddr = if address.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let probe = UdpSocket::bind(wildcard)?;
        crate::protect_std_udp_socket(&probe, protector).map_err(io::Error::other)?;
        probe.connect(SocketAddr::new(address, PORT))?;
        bound(&probe, address)
    }
}

#[cfg(all(test, target_vendor = "apple"))]
pub(super) use apple::{bound, system, RECHECK};

/// Other systems scope nothing here: Android's protector moves the socket
/// out of the VPN, and elsewhere it follows the routes.
#[cfg(not(target_vendor = "apple"))]
impl Scope {
    pub(super) fn open(
        _socket: &UdpSocket,
        _address: IpAddr,
        _protector: Option<&dyn SocketProtector>,
    ) -> io::Result<Self> {
        Ok(Self::KEPT)
    }

    pub(super) fn refresh(
        &self,
        _socket: &UdpSocket,
        _address: IpAddr,
        _protector: Option<&dyn SocketProtector>,
    ) {
    }
}
