//! XDRIVE outbound transports: `xdriveSettings` turned into the storage its
//! sessions live in.
use xray_config::{StreamSecurity, StreamSettings, StreamTransport, XdriveService, XdriveSettings};
use xray_transport::stream::XhttpXmuxPolicy;
use xray_transport::xdrive::{
    keep_alive_for, XdriveConfig, XdriveHttpConfig, XdriveS3, XdriveStorageConfig, XdriveTemplate,
    XdriveTransport, XdriveTuning,
};
use xray_transport::TlsClientConfig;

use super::xhttp::xhttp_range;
use crate::CoreError;

/// The transport of a stream carrying `settings` with `security`. The
/// services this client cannot reach yet refuse to start, as does what
/// Xray-core accepts in its configuration and then fails every dial with:
/// no service, or a `local` folder that is not named. A bad template or S3
/// endpoint fails each dial instead, as in Xray-core.
pub(crate) fn build_xdrive_transport(
    settings: &XdriveSettings,
    security: &StreamSecurity,
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
        XdriveService::GoogleDrive => {
            return refuse("service google-drive is not supported yet".to_owned())
        }
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
                http: http_config(settings, security)?,
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
                http: http_config(settings, security)?,
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
/// hello offering `h2` and `http/1.1`.
fn http_config(
    settings: &XdriveSettings,
    security: &StreamSecurity,
) -> Result<XdriveHttpConfig, CoreError> {
    let tls = match security {
        StreamSecurity::Tls(tls) if tls.alpn == ["h3"] => {
            return Err(CoreError::InvalidXdriveConfiguration(
                r#"a storage over HTTP/3 (alpn ["h3"]) is not supported yet"#.to_owned(),
            ))
        }
        StreamSecurity::Tls(tls) => TlsClientConfig {
            server_name: tls.server_name.clone().unwrap_or_default(),
            allow_insecure: tls.allow_insecure,
            pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
            verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
            alpn: tls.alpn.clone(),
            fingerprint: tls.fingerprint.clone(),
        },
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
    })
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

    fn build(settings: &XdriveSettings) -> Result<XdriveTransport, CoreError> {
        build_xdrive_transport(settings, &StreamSecurity::None)
    }

    #[test]
    fn local_s3_and_template_build_and_the_rest_refuse_with_a_reason() {
        assert!(build(&settings(XdriveService::Local, "/tmp/x")).is_ok());
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
            (
                XdriveService::GoogleDrive,
                "id",
                "google-drive is not supported yet",
            ),
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
        let plain = http_config(&template, &StreamSecurity::None).unwrap();
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
        let shaped = http_config(&template, &tls).unwrap();
        assert_eq!(shaped.tls.server_name, "storage.example");
        assert_eq!(shaped.tls.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(shaped.tls.pinned_peer_cert_sha256, vec![[7; 32]]);
        assert_eq!(shaped.tls.verify_peer_cert_by_name, ["alt.example"]);
        assert_eq!(shaped.tls.alpn, ["h2"]);
    }

    #[test]
    fn storages_over_http3_wait_for_a_later_change() {
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
        let error = build_xdrive_transport(&template, &tls(&["h3"])).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"), "{error}");
        assert!(build_xdrive_transport(&template, &tls(&["h3", "h2"])).is_ok());
        // A local folder takes no connection at all.
        let local = settings(XdriveService::Local, "/tmp/x");
        assert!(build_xdrive_transport(&local, &tls(&["h3"])).is_ok());
    }
}
