//! Which address families the system has a route for, as Xray-core's
//! `utils.CheckRoutes` reports them for `queryStrategy: "UseSystem"`.
//!
//! A UDP `connect` picks a route and a source address without sending
//! anything, so it fails at once for a family the system cannot reach.
//! Xray-core connects to a root DNS server of each family; so does this.
use crate::SocketProtector;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// `b.root-servers.net`, the address Xray-core probes for IPv4.
const IPV4_PROBE: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 33, 4, 12), 53));
/// `b.root-servers.net`, the address Xray-core probes for IPv6.
const IPV6_PROBE: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),
    53,
    0,
    0,
));
/// How long a probe stands where the network can change under the process,
/// as on Xray-core's GUI platforms.
const ROUTE_PROBE_TTL: Duration = Duration::from_millis(100);

/// The address families the system has a route for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteFamilies {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl RouteFamilies {
    /// Both families, as when nothing narrows a lookup.
    pub const BOTH: Self = Self {
        ipv4: true,
        ipv6: true,
    };
}

/// Reports the address families the system has a route for.
pub trait RouteProbe: Send + Sync + fmt::Debug {
    fn families(&self) -> RouteFamilies;
}

/// Probes the system's routes as Xray-core does.
///
/// The probe sockets go through the socket protector, so inside a mobile VPN
/// they see the network the core dials over rather than the VPN's own
/// routes, which Xray-core's unprotected probe sees on Android.
///
/// Where the network can change under the process — Android, iOS, macOS,
/// Windows, or a Linux or BSD desktop session — a probe stands for 100 ms;
/// elsewhere the first one stands for the life of the probe, as in Xray-core.
pub struct SystemRouteProbe {
    protector: Option<Arc<dyn SocketProtector>>,
    ttl: Option<Duration>,
    cached: Mutex<Option<(Instant, RouteFamilies)>>,
}

impl fmt::Debug for SystemRouteProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemRouteProbe")
            .field("protector", &self.protector.is_some())
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl SystemRouteProbe {
    pub fn new(protector: Option<Arc<dyn SocketProtector>>) -> Self {
        Self {
            protector,
            ttl: network_can_change().then_some(ROUTE_PROBE_TTL),
            cached: Mutex::new(None),
        }
    }

    fn probe(&self) -> RouteFamilies {
        RouteFamilies {
            ipv4: self.routes_to(IPV4_PROBE),
            ipv6: self.routes_to(IPV6_PROBE),
        }
    }

    fn routes_to(&self, target: SocketAddr) -> bool {
        let unspecified = match target {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let Ok(socket) = UdpSocket::bind(unspecified) else {
            return false;
        };
        crate::protect_std_udp_socket(&socket, self.protector.as_deref()).is_ok()
            && socket.connect(target).is_ok()
    }
}

impl RouteProbe for SystemRouteProbe {
    fn families(&self) -> RouteFamilies {
        let mut cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if let Some((probed_at, families)) = *cached {
            if self
                .ttl
                .is_none_or(|ttl| now.saturating_duration_since(probed_at) < ttl)
            {
                return families;
            }
        }
        let families = self.probe();
        *cached = Some((now, families));
        families
    }
}

/// Xray-core's `detectGUIPlatform`.
fn network_can_change() -> bool {
    if cfg!(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows"
    )) {
        return true;
    }
    let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    matches!(
        std::env::var("XDG_SESSION_TYPE").as_deref(),
        Ok("wayland" | "x11")
    ) || set("DISPLAY")
        || set("WAYLAND_DISPLAY")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct Counting(AtomicUsize);
    impl SocketProtector for Counting {
        fn protect(&self, _: crate::SocketHandle) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Refusing;
    impl SocketProtector for Refusing {
        fn protect(&self, _: crate::SocketHandle) -> std::io::Result<()> {
            Err(std::io::Error::other("refused"))
        }
    }

    #[test]
    fn probes_go_through_the_protector_and_stand_for_their_ttl() {
        let protector = Arc::new(Counting::default());
        let probe = SystemRouteProbe {
            protector: Some(protector.clone()),
            ttl: Some(Duration::from_secs(60)),
            cached: Mutex::new(None),
        };
        let first = probe.families();
        let protected = protector.0.load(Ordering::SeqCst);
        assert!(protected >= 1, "each probe socket is protected");
        assert_eq!(probe.families(), first);
        assert_eq!(protector.0.load(Ordering::SeqCst), protected);
        *probe.cached.lock().unwrap() = Some((
            Instant::now() - Duration::from_secs(61),
            RouteFamilies::BOTH,
        ));
        probe.families();
        assert!(protector.0.load(Ordering::SeqCst) > protected);
    }

    #[test]
    fn a_probe_without_a_ttl_stands_for_good() {
        let probe = SystemRouteProbe {
            protector: None,
            ttl: None,
            cached: Mutex::new(Some((
                Instant::now() - Duration::from_secs(3600),
                RouteFamilies {
                    ipv4: false,
                    ipv6: true,
                },
            ))),
        };
        assert_eq!(
            probe.families(),
            RouteFamilies {
                ipv4: false,
                ipv6: true
            }
        );
    }

    #[test]
    fn a_socket_the_protector_refuses_has_no_route() {
        let probe = SystemRouteProbe::new(Some(Arc::new(Refusing)));
        assert_eq!(
            probe.families(),
            RouteFamilies {
                ipv4: false,
                ipv6: false
            }
        );
    }
}
