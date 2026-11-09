//! XDRIVE outbound transports: `xdriveSettings` turned into the storage its
//! sessions live in.
use xray_config::{StreamSecurity, StreamSettings, StreamTransport, XdriveService, XdriveSettings};
use xray_transport::xdrive::{XdriveConfig, XdriveStorageConfig, XdriveTransport, XdriveTuning};

use crate::CoreError;

/// The transport of `settings`. The services this client cannot reach yet
/// refuse to start, as does what Xray-core accepts in its configuration
/// and then fails every dial with: no service, or a `local` folder that is
/// not named.
pub(crate) fn build_xdrive_transport(
    settings: &XdriveSettings,
) -> Result<XdriveTransport, CoreError> {
    let storage = match settings.service {
        XdriveService::Unset => {
            return Err(CoreError::InvalidXdriveConfiguration(
                "unsupported service: ".to_owned(),
            ))
        }
        XdriveService::Local => {
            if settings.remote_folder.is_empty() {
                return Err(CoreError::InvalidXdriveConfiguration(
                    r#"empty "remoteFolder""#.to_owned(),
                ));
            }
            XdriveStorageConfig::Local {
                folder: settings.remote_folder.clone(),
            }
        }
        service @ (XdriveService::GoogleDrive | XdriveService::Template | XdriveService::S3) => {
            return Err(CoreError::InvalidXdriveConfiguration(format!(
                "service {} is not supported yet",
                service.name()
            )))
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
        }
    }

    #[test]
    fn local_builds_and_the_rest_refuse_with_a_reason() {
        assert!(build_xdrive_transport(&settings(XdriveService::Local, "/tmp/x")).is_ok());
        for (service, folder, reason) in [
            (XdriveService::Unset, "/tmp/x", "unsupported service: "),
            (XdriveService::Local, "", r#"empty "remoteFolder""#),
            (
                XdriveService::GoogleDrive,
                "id",
                "google-drive is not supported yet",
            ),
            (
                XdriveService::Template,
                "f",
                "template is not supported yet",
            ),
            (XdriveService::S3, "f", "s3 is not supported yet"),
        ] {
            let error = build_xdrive_transport(&settings(service, folder)).unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
    }
}
