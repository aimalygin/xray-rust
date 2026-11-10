//! XDRIVE outbound transports: `xdriveSettings` turned into the storage its
//! sessions live in.
use std::time::Duration;
use xray_config::{StreamSecurity, StreamSettings, StreamTransport, XdriveService, XdriveSettings};

use xray_transport::stream::{H3QuicConfig, XhttpXmuxPolicy};
use xray_transport::xdrive::{
    keep_alive_for, XdriveConfig, XdriveHttpConfig, XdriveS3, XdriveStorageConfig, XdriveTemplate,
    XdriveTransport, XdriveTuning,
};
use xray_transport::TlsClientConfig;

use super::xhttp::{udp_noise_config, xhttp_h3_quic_config, xhttp_range};
use crate::CoreError;

/// The transport of a stream carrying `settings` with `security`. What
/// Xray-core accepts in its configuration and then fails every dial with
/// refuses to start here: no service, or a `local` folder that is not
/// named. A bad template, S3 endpoint or Drive folder fails each dial
/// instead, as in Xray-core.
pub(crate) fn build_xdrive_transport(
    settings: &XdriveSettings,
    stream: &StreamSettings,
) -> Result<XdriveTransport, CoreError> {
    let refuse = |reason: String| Err(CoreError::InvalidXdriveConfiguration(reason));
    let storage = match settings.service {
        XdriveService::Unset => return refuse("unsupported service: ".to_owned()),
        XdriveService::Local => {
            if settings.remote_folder.is_empty() {
                return refuse(r#"empty "remoteFolder""#.to_owned());
            }
            XdriveStorageConfig::Local {
                folder: settings.remote_folder.clone(),
            }
        }
        XdriveService::GoogleDrive => XdriveStorageConfig::GoogleDrive {
            folder: settings.remote_folder.clone(),
            secrets: settings.secrets.clone(),
            http: http_config(settings, stream)?,
        },
        XdriveService::S3 => {
            let Some(s3) = &settings.s3 else {
                return refuse(r#"service "s3" needs an "s3" object"#.to_owned());
            };
            let secret = |index: usize| settings.secrets.get(index).cloned().unwrap_or_default();
            XdriveStorageConfig::S3 {
                s3: XdriveS3 {
                    endpoint: s3.endpoint.clone(),
                    region: s3.region.clone(),
                    bucket: s3.bucket.clone(),
                    path_style: s3.path_style,
                    remote_folder: settings.remote_folder.clone(),
                    access_key: secret(0),
                    secret_key: secret(1),
                    session_token: settings.secrets.get(2).cloned(),
                },
                http: http_config(settings, stream)?,
            }
        }
        XdriveService::Template => {
            let Some(template) = &settings.template else {
                return refuse(r#"service "template" needs a "template" object"#.to_owned());
            };
            XdriveStorageConfig::Template {
                template: XdriveTemplate {
                    template: template.clone(),
                    folder: settings.remote_folder.clone(),
                    secrets: settings.secrets.clone(),
                },
                http: http_config(settings, stream)?,
            }
        }
    };
    Ok(XdriveTransport::new(XdriveConfig {
        storage,
        tuning: XdriveTuning {
            segment_bytes: settings.segment_bytes,
            flush_interval_ms: settings.flush_interval_ms,
            poll_interval_ms: settings.poll_interval_ms,
            max_poll_interval_ms: settings.max_poll_interval_ms,
            session_ttl_seconds: settings.session_ttl_seconds,
            concurrency: settings.concurrency,
            eager_window_ms: settings.eager_window_ms,
            hole_timeout_ms: settings.hole_timeout_ms,
        },
    }))
}

/// How an HTTP storage is reached, as Xray-core's `newServiceClient` reads
/// the stream: its TLS with each URL's host as the server name unless one
/// is given, or without TLS settings Xray-core's default config, a Chrome
/// hello offering `h2` and `http/1.1`; and over `alpn` exactly `["h3"]`,
/// HTTP/3 with the stream's QUIC parameters and UDP masks.
fn http_config(
    settings: &XdriveSettings,
    stream: &StreamSettings,
) -> Result<XdriveHttpConfig, CoreError> {
    let mut h3 = None;
    let tls = match &stream.security {
        StreamSecurity::Tls(tls) => {
            if tls.alpn == ["h3"] {
                h3 = Some(h3_quic(settings, stream)?);
            }
            TlsClientConfig {
                server_name: tls.server_name.clone().unwrap_or_default(),
                allow_insecure: tls.allow_insecure,
                pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                alpn: tls.alpn.clone(),
                fingerprint: tls.fingerprint.clone(),
            }
        }
        // The parser refuses REALITY under XDRIVE, as Xray-core does.
        StreamSecurity::None | StreamSecurity::Reality(_) => TlsClientConfig {
            server_name: String::new(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            // `tls.GetFingerprint("")`: Chrome.
            fingerprint: Some("chrome".to_owned()),
        },
    };
    let xmux = &settings.xmux;
    Ok(XdriveHttpConfig {
        tls,
        fronting: settings.fronting.as_ref().map(|(address, port)| {
            let address = match address {
                xray_config::TargetAddr::Ip(ip) => xray_routing::TargetAddr::Ip(*ip),
                xray_config::TargetAddr::Domain(domain) => {
                    xray_routing::TargetAddr::Domain(domain.clone())
                }
            };
            (address, *port)
        }),
        xmux: XhttpXmuxPolicy {
            max_concurrency: xhttp_range(xmux.max_concurrency),
            max_connections: xhttp_range(xmux.max_connections),
            c_max_reuse_times: xhttp_range(xmux.c_max_reuse_times),
            h_max_request_times: xhttp_range(xmux.h_max_request_times),
            h_max_reusable_secs: xhttp_range(xmux.h_max_reusable_secs),
            h_keep_alive_period_secs: xmux.h_keep_alive_period_secs,
        },
        keep_alive: keep_alive_for(xmux.h_keep_alive_period_secs),
        h3,
    })
}

/// The QUIC connections of a storage over HTTP/3, as Xray-core configures
/// quic-go for them: `quicParams` as XHTTP takes them, a keepalive only
/// when asked for, there or by a positive `xmux.hKeepAlivePeriod`, and the
/// stream's UDP masks.
fn h3_quic(settings: &XdriveSettings, stream: &StreamSettings) -> Result<H3QuicConfig, CoreError> {
    let invalid = |error: CoreError| CoreError::InvalidXdriveConfiguration(error.to_string());
    let params = stream.quic_params.as_ref();
    let mut config = xhttp_h3_quic_config(params).map_err(invalid)?;
    // Xray-core parrots Chrome here unless `disableChromeParrot`; this client
    // keeps Quinn's own handshake for now, and the parser warns about it.
    config.chrome_parrot = false;
    if params.is_none_or(|params| params.keep_alive_period_secs == 0) {
        let period = settings.xmux.h_keep_alive_period_secs;
        config.keep_alive_interval = (period > 0).then(|| Duration::from_secs(period as u64));
    }
    config.udp_noise = stream
        .udp_noise
        .as_ref()
        .map(udp_noise_config)
        .transpose()
        .map_err(invalid)?;
    config.udp_header_custom = stream
        .udp_header_custom
        .as_ref()
        .map(super::carrier::quic_header_custom);
    config.udp_sudoku = stream.udp_sudoku.as_ref().map(super::carrier::quic_sudoku);
    config.udp_xdns = stream.udp_xdns.as_ref().map(super::carrier::xdns_config);
    config.udp_realm = stream.udp_realm.as_ref().map(super::carrier::realm_config);
    config.udp_xicmp = stream.udp_xicmp.as_ref().map(super::carrier::xicmp_config);
    // Salamander as on XHTTP over HTTP/3, at its place among the masks.
    config.udp_salamander = stream
        .udp_salamander
        .as_ref()
        .map(super::carrier::quic_salamander)
        .transpose()?;
    Ok(config)
}

/// Whether `stream` is XDRIVE reaching its storage over HTTP/3, which
/// Xray-core does only when `alpn` is exactly `["h3"]`: its UDP masks then
/// shape that storage's QUIC connection.
pub(crate) fn is_xdrive_h3(stream: &StreamSettings) -> bool {
    matches!(stream.transport, StreamTransport::Xdrive(_))
        && matches!(&stream.security, StreamSecurity::Tls(tls) if tls.alpn == ["h3"])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(service: XdriveService, folder: &str) -> XdriveSettings {
        XdriveSettings {
            service,
            remote_folder: folder.to_owned(),
            secrets: Vec::new(),
            segment_bytes: 0,
            flush_interval_ms: 0,
            poll_interval_ms: 0,
            max_poll_interval_ms: 0,
            session_ttl_seconds: 0,
            concurrency: 0,
            eager_window_ms: 0,
            hole_timeout_ms: 0,
            template: None,
            s3: None,
            xmux: xray_config::xdrive_default_xmux(1),
            fronting: None,
        }
    }

    /// A stream of `settings` with `security` and nothing else.
    fn stream(settings: &XdriveSettings, security: StreamSecurity) -> StreamSettings {
        StreamSettings {
            network: xray_config::Network::Tcp,
            transport: StreamTransport::Xdrive(Box::new(settings.clone())),
            security,
            quic_params: None,
            tcp_fragment: None,
            tcp_header_custom: None,
            udp_header_custom: None,
            tcp_sudoku: None,
            udp_sudoku: None,
            tcp_xmc: None,
            udp_xdns: None,
            udp_realm: None,
            udp_xicmp: None,
            udp_noise: None,
            udp_salamander: None,
            socket_options: None,
        }
    }

    fn build(settings: &XdriveSettings) -> Result<XdriveTransport, CoreError> {
        build_xdrive_transport(settings, &stream(settings, StreamSecurity::None))
    }

    #[test]
    fn every_service_builds_and_what_xray_fails_at_each_dial_refuses() {
        assert!(build(&settings(XdriveService::Local, "/tmp/x")).is_ok());
        // Xray-core checks the folder and secrets at the first dial.
        assert!(build(&settings(XdriveService::GoogleDrive, "")).is_ok());
        let mut s3 = settings(XdriveService::S3, "prefix");
        s3.s3 = Some(xray_config::XdriveS3Settings {
            endpoint: "https://s3.example".to_owned(),
            region: String::new(),
            bucket: "bucket".to_owned(),
            path_style: true,
        });
        s3.secrets = vec![
            zeroize::Zeroizing::new("AKID".to_owned()),
            zeroize::Zeroizing::new("secret".to_owned()),
        ];
        assert!(build(&s3).is_ok());
        let mut template = settings(XdriveService::Template, "folder");
        // Xray-core reads the template at the first dial, so a broken one
        // still builds.
        template.template = Some(zeroize::Zeroizing::new("{}".to_owned()));
        assert!(build(&template).is_ok());
        for (service, folder, reason) in [
            (XdriveService::Unset, "/tmp/x", "unsupported service: "),
            (XdriveService::Local, "", r#"empty "remoteFolder""#),
            (XdriveService::Template, "f", r#"needs a "template" object"#),
            (XdriveService::S3, "f", r#"needs an "s3" object"#),
        ] {
            let error = build(&settings(service, folder)).unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
    }

    #[test]
    fn http_storages_take_the_streams_tls_or_a_chrome_hello() {
        let mut template = settings(XdriveService::Template, "folder");
        template.fronting = Some((
            xray_config::TargetAddr::Domain("front.example".to_owned()),
            8443,
        ));
        template.xmux.h_keep_alive_period_secs = -1;
        let plain = http_config(&template, &stream(&template, StreamSecurity::None)).unwrap();
        assert_eq!(plain.tls.fingerprint.as_deref(), Some("chrome"));
        assert!(plain.tls.server_name.is_empty() && plain.tls.alpn.is_empty());
        assert_eq!(
            plain.fronting,
            Some((
                xray_routing::TargetAddr::Domain("front.example".to_owned()),
                8443
            ))
        );
        assert_eq!(plain.keep_alive, None);
        assert_eq!(plain.xmux.h_max_reusable_secs.from, 1800);
        let tls = StreamSecurity::Tls(xray_config::TlsSettings {
            server_name: Some("storage.example".to_owned()),
            fingerprint: Some("firefox".to_owned()),
            pinned_peer_cert_sha256: vec![[7; 32]],
            verify_peer_cert_by_name: vec!["alt.example".to_owned()],
            allow_insecure: false,
            alpn: vec!["h2".to_owned()],
        });
        let shaped = http_config(&template, &stream(&template, tls)).unwrap();
        assert!(shaped.h3.is_none());
        assert_eq!(shaped.tls.server_name, "storage.example");
        assert_eq!(shaped.tls.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(shaped.tls.pinned_peer_cert_sha256, vec![[7; 32]]);
        assert_eq!(shaped.tls.verify_peer_cert_by_name, ["alt.example"]);
        assert_eq!(shaped.tls.alpn, ["h2"]);
    }

    #[test]
    fn storages_over_http3_take_quic_with_xrays_keepalive() {
        let mut template = settings(XdriveService::Template, "folder");
        template.template = Some(zeroize::Zeroizing::new("{}".to_owned()));
        let tls = |alpn: &[&str]| {
            StreamSecurity::Tls(xray_config::TlsSettings {
                server_name: None,
                fingerprint: Some("chrome".to_owned()),
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                allow_insecure: false,
                alpn: alpn.iter().map(|p| (*p).to_owned()).collect(),
            })
        };
        let h3 = http_config(&template, &stream(&template, tls(&["h3"]))).unwrap();
        let quic = h3.h3.expect("HTTP/3 over exactly h3");
        // No keepalive unless asked for, as quic-go in Xray-core.
        assert_eq!(quic.keep_alive_interval, None);
        template.xmux.h_keep_alive_period_secs = 20;
        let quic = http_config(&template, &stream(&template, tls(&["h3"])))
            .unwrap()
            .h3
            .unwrap();
        assert_eq!(quic.keep_alive_interval, Some(Duration::from_secs(20)));
        assert!(
            http_config(&template, &stream(&template, tls(&["h3", "h2"])))
                .unwrap()
                .h3
                .is_none()
        );
        assert!(build_xdrive_transport(&template, &stream(&template, tls(&["h3"]))).is_ok());
    }

    #[test]
    fn storages_over_http3_carry_the_streams_udp_masks() {
        let raw = serde_json::json!({"outbounds": [{"protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": 443,
                "id": "27848739-7e62-4138-9fd3-098a63964b6b",
                "encryption": "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I"},
            "streamSettings": {"network": "xdrive", "security": "tls",
                "tlsSettings": {"alpn": ["h3"]},
                "finalmask": {"udp": [{"type": "noise", "settings": {"noise": [{"rand": "30-60"}]}}],
                    "quicParams": {"disableChromeParrot": true, "maxIdleTimeout": 12}},
                "xdriveSettings": {"service": "google-drive", "remoteFolder": "id",
                    "secrets": ["a", "b", "c"]}},
            "mux": {"enabled": true}}]})
        .to_string();
        let parsed = xray_config::parse_xray_json(&raw).unwrap();
        let stream = &parsed.config.outbounds[0].stream;
        let StreamTransport::Xdrive(xdrive) = &stream.transport else {
            panic!("not XDRIVE")
        };
        let quic = http_config(xdrive, stream).unwrap().h3.unwrap();
        assert!(quic.udp_noise.is_some());
        assert_eq!(quic.max_idle_timeout, Duration::from_secs(12));
    }

    #[test]
    fn storages_over_http3_take_salamander_as_xhttp_h3_does() {
        // Xray-core's XDRIVE dial wraps its UDP socket in every FinalMask UDP
        // mask, Salamander among them; Google Drive over h3 takes only noise.
        let raw = serde_json::json!({"outbounds": [{"protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": 443,
                "id": "27848739-7e62-4138-9fd3-098a63964b6b",
                "encryption": "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I"},
            "streamSettings": {"network": "xdrive", "security": "tls",
                "tlsSettings": {"alpn": ["h3"]},
                "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "salamander-password"}}],
                    "quicParams": {"disableChromeParrot": true}},
                "xdriveSettings": {"service": "s3", "remoteFolder": "prefix",
                    "secrets": ["AKID", "secret"],
                    "s3": {"endpoint": "https://s3.example", "bucket": "bucket"}}},
            "mux": {"enabled": true}}]})
        .to_string();
        let parsed = xray_config::parse_xray_json(&raw).unwrap();
        let stream = &parsed.config.outbounds[0].stream;
        let StreamTransport::Xdrive(xdrive) = &stream.transport else {
            panic!("not XDRIVE")
        };
        let quic = http_config(xdrive, stream).unwrap().h3.unwrap();
        assert!(quic.udp_salamander.is_some());
        assert!(build_xdrive_transport(xdrive, stream).is_ok());
    }
}
