//! An outbound's `streamSettings.sockopt`, compiled into the options every
//! socket it opens takes.
use std::{borrow::Cow, sync::Arc};

use xray_config::{SocketOptions as ConfigSocketOptions, StreamSettings, TproxyMode};
use xray_transport::{CustomSocketOption, SocketOptions, TransportDialer};

/// The options `stream`'s sockets take, or `None` when it sets none and the
/// dialer's defaults apply.
pub(crate) fn compile(stream: &StreamSettings) -> Option<Arc<SocketOptions>> {
    compile_options(stream.socket_options.as_ref()?)
}

pub(crate) fn compile_options(options: &ConfigSocketOptions) -> Option<Arc<SocketOptions>> {
    let compiled = SocketOptions {
        mark: options.mark,
        tcp_fast_open: options.tcp_fast_open,
        transparent: options.tproxy != TproxyMode::Off,
        tcp_keep_alive_idle: options.tcp_keep_alive_idle,
        tcp_keep_alive_interval: options.tcp_keep_alive_interval,
        tcp_congestion: options.tcp_congestion.clone(),
        tcp_window_clamp: options.tcp_window_clamp,
        tcp_max_seg: options.tcp_max_seg,
        tcp_user_timeout: options.tcp_user_timeout,
        interface: options.interface.clone(),
        multipath_tcp: options.tcp_mptcp,
        custom: options
            .custom
            .iter()
            .map(|custom| CustomSocketOption {
                system: custom.system.clone(),
                network: custom.network.clone(),
                level: custom.level.clone(),
                opt: custom.opt.clone(),
                value: custom.value.clone(),
                kind: custom.kind.clone(),
            })
            .collect(),
    };
    (compiled != SocketOptions::default()).then(|| Arc::new(compiled))
}

/// `dialer` with `options`, or `dialer` itself when there are none.
pub(crate) fn dialer<'a>(
    dialer: &'a TransportDialer,
    options: Option<&Arc<SocketOptions>>,
) -> Cow<'a, TransportDialer> {
    match options {
        Some(options) => Cow::Owned(dialer.clone().with_socket_options(Arc::clone(options))),
        None => Cow::Borrowed(dialer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_config::CustomSocketOption as ConfigCustomSocketOption;

    #[test]
    fn options_that_set_nothing_on_a_socket_keep_the_dialers_defaults() {
        assert_eq!(compile_options(&ConfigSocketOptions::default()), None);
        let dial_only = ConfigSocketOptions {
            domain_strategy: xray_config::DomainStrategy::UseIpv4,
            penetrate: true,
            happy_eyeballs: Some(Default::default()),
            ..ConfigSocketOptions::default()
        };
        assert_eq!(compile_options(&dial_only), None);
    }

    #[test]
    fn every_socket_option_is_compiled() {
        let options = ConfigSocketOptions {
            mark: 7,
            tcp_fast_open: 256,
            tproxy: TproxyMode::Redirect,
            tcp_keep_alive_idle: 30,
            tcp_keep_alive_interval: -1,
            tcp_congestion: "bbr".to_owned(),
            tcp_window_clamp: 600,
            tcp_max_seg: 1200,
            tcp_user_timeout: 5000,
            interface: "eth0".to_owned(),
            tcp_mptcp: true,
            custom: vec![ConfigCustomSocketOption {
                system: "linux".to_owned(),
                network: "tcp".to_owned(),
                level: "6".to_owned(),
                opt: "1".to_owned(),
                value: "1".to_owned(),
                kind: "int".to_owned(),
            }],
            ..ConfigSocketOptions::default()
        };
        let compiled = compile_options(&options).expect("options set on sockets");
        assert_eq!(
            *compiled,
            SocketOptions {
                mark: 7,
                tcp_fast_open: 256,
                transparent: true,
                tcp_keep_alive_idle: 30,
                tcp_keep_alive_interval: -1,
                tcp_congestion: "bbr".to_owned(),
                tcp_window_clamp: 600,
                tcp_max_seg: 1200,
                tcp_user_timeout: 5000,
                interface: "eth0".to_owned(),
                multipath_tcp: true,
                custom: vec![CustomSocketOption {
                    system: "linux".to_owned(),
                    network: "tcp".to_owned(),
                    level: "6".to_owned(),
                    opt: "1".to_owned(),
                    value: "1".to_owned(),
                    kind: "int".to_owned(),
                }],
            }
        );
        let tproxy = ConfigSocketOptions {
            tproxy: TproxyMode::Tproxy,
            ..ConfigSocketOptions::default()
        };
        assert!(compile_options(&tproxy).is_some_and(|options| options.transparent));
    }
}
