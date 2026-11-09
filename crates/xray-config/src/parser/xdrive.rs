//! `xdriveSettings`, read as Xray-core v26.10.31's `XDriveConfig.Build`
//! reads them, with the checks its `StreamConfig.Build` adds for XDRIVE over
//! HTTP/3 and the ones `validateXDrive` makes of the outbound XDRIVE carries.
use super::go_url;
use super::*;
use crate::{xdrive_default_xmux, XdriveS3Settings, XdriveService, XdriveSettings};
use zeroize::Zeroizing;

/// The tuning numbers of `xdriveSettings`, Go `uint32`s, in the order the
/// model keeps them.
const XDRIVE_NUMBERS: [&str; 8] = [
    "segmentBytes",
    "flushIntervalMs",
    "pollIntervalMs",
    "maxPollIntervalMs",
    "sessionTtlSeconds",
    "concurrency",
    "eagerWindowMs",
    "holeTimeoutMs",
];

impl Parser<'_> {
    /// `xdriveSettings` of the stream at `index`. `h3` says the stream runs
    /// XDRIVE with `alpn` exactly `["h3"]`: Google Drive then takes one
    /// connection by default instead of four.
    pub(super) fn parse_xdrive_transport(
        &mut self,
        stream: Option<&Value>,
        index: usize,
        h3: bool,
    ) -> Option<XdriveSettings> {
        let path = format!("$.outbounds[{index}].streamSettings.xdriveSettings");
        let settings = match stream.and_then(|s| s.get("xdriveSettings")) {
            // Xray-core then keeps the transport's registered default: an
            // empty service, which fails every dial, and no xmux at all.
            None | Some(Value::Null) => {
                return Some(XdriveSettings {
                    service: XdriveService::Unset,
                    remote_folder: String::new(),
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
                    xmux: zero_xhttp_xmux_settings(),
                    fronting: None,
                })
            }
            Some(settings @ Value::Object(_)) => settings,
            Some(_) => {
                self.error(path, "xdriveSettings must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(settings, &path, &surface::XDRIVE);
        let remote_folder =
            self.nullable_string_at(settings, "remoteFolder", format!("{path}.remoteFolder"));
        let service = self.nullable_string_at(settings, "service", format!("{path}.service"));
        let secrets = self.xdrive_secrets(settings, &path);
        let numbers =
            XDRIVE_NUMBERS.map(|key| self.nullable_u32_at(settings, key, format!("{path}.{key}")));
        // A json.RawMessage: any value, null included, counts as given.
        let template = settings
            .get("template")
            .map(|template| Zeroizing::new(template.to_string()));
        let s3 = self.xdrive_s3(settings, &path);
        let xmux = self.parse_zeroable_xmux(settings, &path);
        let (remote_folder, service, secrets, s3, xmux) =
            (remote_folder?, service?, secrets?, s3?, xmux?);
        let [segment_bytes, flush_interval_ms, poll_interval_ms, max_poll_interval_ms, session_ttl_seconds, concurrency, eager_window_ms, hole_timeout_ms] =
            numbers;

        let service = match service {
            "local" => XdriveService::Local,
            "Google Drive" => {
                self.warning(
                    format!("{path}.service"),
                    r#"`"service": "Google Drive"` is deprecated; use `"service": "google-drive"`"#,
                );
                XdriveService::GoogleDrive
            }
            "google-drive" => XdriveService::GoogleDrive,
            "template" => XdriveService::Template,
            "s3" => XdriveService::S3,
            other => {
                self.error(
                    format!("{path}.service"),
                    format!(
                        r#"unknown "service": "{other}", use "google-drive", "template", "s3" or "local""#
                    ),
                );
                return None;
            }
        };
        let mut valid = true;
        match service {
            XdriveService::GoogleDrive if secrets.len() != 3 => {
                self.error(
                    format!("{path}.secrets"),
                    "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken",
                );
                valid = false;
            }
            XdriveService::Template if template.is_none() => {
                self.error(
                    format!("{path}.template"),
                    r#"service "template" needs a "template" object"#,
                );
                valid = false;
            }
            XdriveService::S3 if s3.is_none() => {
                self.error(format!("{path}.s3"), r#"service "s3" needs an "s3" object"#);
                valid = false;
            }
            _ => {}
        }
        if xmux.max_connections.to > 0 && xmux.max_concurrency.to > 0 {
            self.error(
                format!("{path}.xmux"),
                "maxConnections cannot be specified together with maxConcurrency",
            );
            valid = false;
        }
        let xmux = if xmux == zero_xhttp_xmux_settings() {
            xdrive_default_xmux(if service == XdriveService::GoogleDrive && !h3 {
                4
            } else {
                1
            })
        } else {
            xmux
        };
        // Only an "s3" service reads the block, and only then is it checked.
        let s3 = if service == XdriveService::S3 {
            s3
        } else {
            None
        };
        if let Some(s3) = &s3 {
            if let Err(error) = validate_s3(s3, remote_folder, &secrets) {
                self.error(&path, error);
                valid = false;
            }
        }
        if !valid {
            return None;
        }
        Some(XdriveSettings {
            service,
            remote_folder: remote_folder.to_owned(),
            secrets,
            segment_bytes: segment_bytes?,
            flush_interval_ms: flush_interval_ms?,
            poll_interval_ms: poll_interval_ms?,
            max_poll_interval_ms: max_poll_interval_ms?,
            session_ttl_seconds: session_ttl_seconds?,
            concurrency: concurrency?,
            eager_window_ms: eager_window_ms?,
            hole_timeout_ms: hole_timeout_ms?,
            template,
            s3,
            xmux,
            fronting: None,
        })
    }

    /// `streamSettings.address` and `port`, which Xray-core reads into every
    /// stream and only XDRIVE dials: an `Address` and a Go `uint16`. Any
    /// other transport still refuses them.
    pub(super) fn parse_stream_fronting(
        &mut self,
        stream: Option<&Value>,
        network: StreamNetwork,
        index: usize,
    ) -> Option<Option<(TargetAddr, u16)>> {
        let Some(stream) = stream else {
            return Some(None);
        };
        let path = format!("$.outbounds[{index}].streamSettings");
        if network != StreamNetwork::Xdrive {
            for key in ["address", "port"] {
                if stream.get(key).is_some() {
                    self.error(child_path(&path, key), format!("unsupported field `{key}`"));
                }
            }
            return Some(None);
        }
        let port = self.nullable_u16_at(stream, "port", format!("{path}.port"));
        let address = match stream.get("address") {
            None | Some(Value::Null) => None,
            // Xray-core looks for the prefix before it trims the address.
            Some(Value::String(text)) if text.starts_with("env:") => {
                self.error(
                    format!("{path}.address"),
                    "streamSettings address environment references are not supported",
                );
                return None;
            }
            Some(Value::String(text)) => {
                let text = normalize_xray_address_text(text);
                Some(
                    parse_xray_ip_address(text)
                        .map(TargetAddr::Ip)
                        .unwrap_or_else(|| TargetAddr::Domain(text.to_owned())),
                )
            }
            Some(_) => {
                self.error(
                    format!("{path}.address"),
                    "invalid address: field `address` must be a string or null",
                );
                return None;
            }
        };
        let port = port?;
        Some(address.map(|address| (address, port)))
    }

    /// `secrets`, a Go `[]string`: null reads as none and a null entry as
    /// an empty string.
    fn xdrive_secrets(&mut self, settings: &Value, path: &str) -> Option<Vec<Zeroizing<String>>> {
        let path = format!("{path}.secrets");
        let entries = match settings.get("secrets") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(entries)) => entries,
            Some(_) => {
                self.error(path, "field `secrets` must be an array of strings");
                return None;
            }
        };
        let mut secrets = Vec::with_capacity(entries.len());
        let mut valid = true;
        for (index, entry) in entries.iter().enumerate() {
            match entry {
                Value::String(secret) => secrets.push(Zeroizing::new(secret.clone())),
                Value::Null => secrets.push(Zeroizing::new(String::new())),
                _ => {
                    self.error(format!("{path}[{index}]"), "secrets must be strings");
                    valid = false;
                }
            }
        }
        valid.then_some(secrets)
    }

    /// `s3`, a Go pointer: null reads as absent.
    fn xdrive_s3(&mut self, settings: &Value, path: &str) -> Option<Option<XdriveS3Settings>> {
        let path = format!("{path}.s3");
        let s3 = match settings.get("s3") {
            None | Some(Value::Null) => return Some(None),
            Some(s3 @ Value::Object(_)) => s3,
            Some(_) => {
                self.error(path, "field `s3` must be an object or null");
                return None;
            }
        };
        self.reject_unknown_fields(s3, &path, &surface::XDRIVE_S3);
        let endpoint = self.nullable_string_at(s3, "endpoint", format!("{path}.endpoint"));
        let region = self.nullable_string_at(s3, "region", format!("{path}.region"));
        let bucket = self.nullable_string_at(s3, "bucket", format!("{path}.bucket"));
        // A *bool: absent or null leaves path-style addressing on.
        let path_style = match s3.get("pathStyle") {
            None | Some(Value::Null) => Some(true),
            Some(Value::Bool(path_style)) => Some(*path_style),
            Some(_) => {
                self.error(
                    format!("{path}.pathStyle"),
                    "field `pathStyle` must be a boolean or null",
                );
                None
            }
        };
        Some(Some(XdriveS3Settings {
            endpoint: endpoint?.to_owned(),
            region: region?.to_owned(),
            bucket: bucket?.to_owned(),
            path_style: path_style?,
        }))
    }

    /// `xmux` as a non-pointer Go `XmuxConfig` reads it: absent or null
    /// keeps every field zero. The caller replaces an all-zero value with its
    /// defaults.
    pub(super) fn parse_zeroable_xmux(
        &mut self,
        settings: &Value,
        path: &str,
    ) -> Option<XhttpXmuxSettings> {
        let xmux = match settings.get("xmux") {
            None | Some(Value::Null) => return Some(zero_xhttp_xmux_settings()),
            Some(xmux @ Value::Object(_)) => xmux,
            Some(_) => {
                self.error(format!("{path}.xmux"), "xmux must be an object");
                return None;
            }
        };
        let xmux_path = format!("{path}.xmux");
        self.reject_unknown_fields(xmux, &xmux_path, &surface::XMUX);
        Some(XhttpXmuxSettings {
            max_concurrency: self.xhttp_range_at(xmux, "maxConcurrency", &xmux_path)?,
            max_connections: self.xhttp_range_at(xmux, "maxConnections", &xmux_path)?,
            c_max_reuse_times: self.xhttp_range_at(xmux, "cMaxReuseTimes", &xmux_path)?,
            h_max_request_times: self.xhttp_range_at(xmux, "hMaxRequestTimes", &xmux_path)?,
            h_max_reusable_secs: self.xhttp_range_at(xmux, "hMaxReusableSecs", &xmux_path)?,
            h_keep_alive_period_secs: self.xhttp_nullable_i64_at(
                xmux,
                "hKeepAlivePeriod",
                format!("{xmux_path}.hKeepAlivePeriod"),
            )?,
        })
    }

    /// What Xray-core's `StreamConfig.Build` refuses of XDRIVE over HTTP/3:
    /// Google Drive under a UDP mask other than `noise`, which changes
    /// datagrams Google cannot undo, and brutal congestion control, which is
    /// for Hysteria servers.
    pub(super) fn validate_xdrive_h3_stream(
        &mut self,
        stream: Option<&Value>,
        transport: &StreamTransport,
        quic_params: Option<&QuicParamsSettings>,
        index: usize,
    ) {
        let Some(finalmask) = stream
            .and_then(|s| s.get("finalmask"))
            .filter(|f| !f.is_null())
        else {
            return;
        };
        let finalmask_path = format!("$.outbounds[{index}].streamSettings.finalmask");
        if matches!(transport, StreamTransport::Xdrive(xdrive) if xdrive.service == XdriveService::GoogleDrive)
        {
            for (mask_index, mask) in finalmask
                .get("udp")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .enumerate()
            {
                let kind = mask.get("type").and_then(Value::as_str).unwrap_or_default();
                if crate::go_lowercase(kind) != "noise" {
                    self.error(
                        format!("{finalmask_path}.udp[{mask_index}].type"),
                        format!(
                            r#"XDRIVE: over h3 to Google Drive the only "udp" mask that works is "noise", not "{kind}""#
                        ),
                    );
                }
            }
        }
        if let Some(quic) = quic_params {
            let congestion = match quic.congestion {
                QuicCongestion::Brutal => Some("brutal"),
                QuicCongestion::ForceBrutal => Some("force-brutal"),
                _ => None,
            };
            if let Some(congestion) = congestion {
                self.error(
                    format!("{finalmask_path}.quicParams.congestion"),
                    format!(
                        r#"XDRIVE: brutal is for Hysteria servers, over h3 "congestion" is "bbr" or "reno", not "{congestion}""#
                    ),
                );
            }
        }
    }

    /// What Xray-core's `validateXDrive` asks of an outbound over XDRIVE:
    /// VLESS with `encryption`, without `flow` or `testpre`, and Mux.Cool
    /// carrying every connection, TCP and UDP, so that one storage session
    /// serves many.
    pub(super) fn validate_xdrive_pair(
        &mut self,
        settings: &OutboundSettings,
        stream: &StreamSettings,
        mux: Option<&crate::MuxSettings>,
        index: usize,
    ) {
        if !matches!(stream.transport, StreamTransport::Xdrive(_)) {
            return;
        }
        let path = format!("$.outbounds[{index}]");
        let OutboundSettings::Vless(vless) = settings else {
            self.error(
                format!("{path}.protocol"),
                "the xdrive transport can only be used by VLESS",
            );
            return;
        };
        let Some(user) = vless.users.first() else {
            return;
        };
        if user.flow.is_some() {
            self.error(
                format!("{path}.settings"),
                r#"the xdrive transport doesn't support VLESS "flow""#,
            );
            return;
        }
        if user.encryption.is_none() {
            self.error(
                format!("{path}.settings"),
                r#"the xdrive transport needs VLESS "encryption", run "xray vlessenc" to get one"#,
            );
            return;
        }
        // A VLESS `reverse` opens its own Mux; it is refused here anyway.
        if mux.is_none_or(|mux| {
            mux.concurrency < 0 || mux.xudp_concurrency < 0 || mux.udp443 == crate::MuxUdp443::Skip
        }) {
            self.error(
                format!("{path}.mux"),
                r#"the xdrive transport needs "mux" enabled, with no negative "concurrency" or "xudpConcurrency" and no "xudpProxyUDP443":"skip""#,
            );
            return;
        }
        if user.pre_connections != 0 {
            self.error(
                format!("{path}.settings"),
                r#"the xdrive transport doesn't support VLESS "testpre""#,
            );
        }
    }
}

/// Xray-core's `ValidateS3Config`: the endpoint, region, bucket, folder and
/// secrets an `s3` service signs and addresses its requests with.
fn validate_s3(
    s3: &XdriveS3Settings,
    remote_folder: &str,
    secrets: &[Zeroizing<String>],
) -> Result<(), &'static str> {
    let endpoint = go_url::parse(&s3.endpoint).ok().filter(|url| {
        matches!(url.scheme.as_str(), "http" | "https")
            && !url.hostname().is_empty()
            && url.user.is_none()
            && url.raw_query.is_empty()
            && !url.force_query
            && url.fragment.is_empty()
            && url.opaque.is_empty()
    });
    let Some(endpoint) = endpoint else {
        return Err("S3 endpoint must be an http(s) URL without credentials, query or fragment");
    };
    if !valid_header_field_value(&s3.region) || s3.region.contains(['/', ',', ' ', '\t']) {
        return Err("invalid S3 signing region");
    }
    if !valid_s3_name(&s3.bucket) || s3.bucket.contains('/') {
        return Err("S3 needs a bucket name without path separators");
    }
    if !s3.path_style {
        if go_parse_ip(endpoint.hostname()) {
            return Err("S3 virtual-hosted addressing requires a DNS endpoint");
        }
        // The bucket becomes part of the HTTP authority, not of the path.
        let bucket = &s3.bucket;
        if !bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            || bucket.contains("..")
            || bucket.starts_with('.')
            || bucket.ends_with('.')
        {
            return Err("S3 virtual-hosted addressing requires a DNS-compatible bucket name");
        }
    }
    if !valid_s3_name(remote_folder.strip_suffix('/').unwrap_or(remote_folder)) {
        return Err(
            "S3 remoteFolder must be a nonempty relative prefix without empty, '.' or '..' components",
        );
    }
    if !(2..=3).contains(&secrets.len()) || secrets[0].is_empty() || secrets[1].is_empty() {
        return Err("S3 needs AccessKeyID, SecretAccessKey and optionally SessionToken in secrets");
    }
    if secrets
        .iter()
        .any(|secret| !valid_header_field_value(secret))
    {
        return Err("invalid S3 secret");
    }
    if secrets[0].contains(['/', ' ', ',', '\t']) {
        return Err("invalid S3 AccessKeyID");
    }
    Ok(())
}

/// Xray-core's `validS3Name`: no control character or backslash, and
/// `/`-separated parts none of which is empty, `.` or `..`.
pub(crate) fn valid_s3_name(name: &str) -> bool {
    !name
        .chars()
        .any(|ch| (ch as u32) < 0x20 || ch == '\u{7f}' || ch == '\\')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// `httpguts.ValidHeaderFieldValue`: no control byte but horizontal tab.
fn valid_header_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// Whether Go's `net.ParseIP` takes `host`: an IPv4 address in dotted
/// decimal without leading zeros, or an IPv6 address without a zone.
fn go_parse_ip(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(endpoint: &str, bucket: &str, path_style: bool) -> XdriveS3Settings {
        XdriveS3Settings {
            endpoint: endpoint.to_owned(),
            region: String::new(),
            bucket: bucket.to_owned(),
            path_style,
        }
    }

    fn secrets(values: &[&str]) -> Vec<Zeroizing<String>> {
        values
            .iter()
            .map(|value| Zeroizing::new((*value).to_owned()))
            .collect()
    }

    #[test]
    fn s3_names_refuse_empty_dot_and_control_parts() {
        for name in ["a", "a/b", "a.b/c-d", "x y", "é"] {
            assert!(valid_s3_name(name), "{name}");
        }
        for name in [
            "", "/a", "a/", "a//b", ".", "a/./b", "..", "a\\b", "a\u{1}b", "a\u{7f}",
        ] {
            assert!(!valid_s3_name(name), "{name:?}");
        }
    }

    #[test]
    fn s3_endpoints_are_plain_http_urls() {
        let keys = secrets(&["AKID", "secret"]);
        for endpoint in [
            "https://s3.example",
            "http://127.0.0.1:9000",
            "HTTPS://s3.example/prefix/",
            "https://s3.example#",
        ] {
            assert_eq!(
                validate_s3(&s3(endpoint, "bucket", true), "folder", &keys),
                Ok(()),
                "{endpoint}"
            );
        }
        for endpoint in [
            "",
            "ftp://s3.example",
            "https://",
            "https://:443",
            "https://user@s3.example",
            "https://s3.example/?",
            "https://s3.example/?a=b",
            "https://s3.example/#frag",
            "https:s3.example",
            "https://s3.example:port",
        ] {
            assert!(
                validate_s3(&s3(endpoint, "bucket", true), "folder", &keys).is_err(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn virtual_hosted_addressing_needs_a_dns_endpoint_and_bucket() {
        let keys = secrets(&["AKID", "secret"]);
        assert_eq!(
            validate_s3(&s3("https://s3.example", "my-bucket.1", false), "f", &keys),
            Ok(())
        );
        for (endpoint, bucket) in [
            ("https://192.0.2.1", "bucket"),
            ("https://[2001:db8::1]:9000", "bucket"),
            ("https://s3.example", "Bucket"),
            ("https://s3.example", "a..b"),
            ("https://s3.example", ".bucket"),
            ("https://s3.example", "bucket."),
            ("https://s3.example", "under_score"),
        ] {
            assert!(
                validate_s3(&s3(endpoint, bucket, false), "f", &keys).is_err(),
                "{endpoint} {bucket}"
            );
        }
        // A zone is not an IP address to net.ParseIP.
        assert_eq!(
            validate_s3(&s3("https://[fe80::1%25en0]", "bucket", false), "f", &keys),
            Ok(())
        );
    }

    #[test]
    fn s3_secrets_are_two_or_three_header_values() {
        let check = |values: &[&str]| {
            validate_s3(&s3("https://s3.example", "b", true), "f", &secrets(values))
        };
        assert_eq!(check(&["AKID", "secret"]), Ok(()));
        assert_eq!(check(&["AKID", "secret", "token"]), Ok(()));
        assert_eq!(check(&["AKID", "secret", ""]), Ok(()));
        assert!(check(&["AKID"]).is_err());
        assert!(check(&["", "secret"]).is_err());
        assert!(check(&["AKID", ""]).is_err());
        assert!(check(&["AKID", "secret", "token", "more"]).is_err());
        assert!(check(&["AKID", "sec\nret"]).is_err());
        assert!(check(&["AK/ID", "secret"]).is_err());
        assert!(check(&["AK ID", "secret"]).is_err());
        assert_eq!(check(&["AKID", "sec\tret"]), Ok(()));
    }

    #[test]
    fn s3_folder_loses_one_trailing_slash() {
        let keys = secrets(&["AKID", "secret"]);
        let bucket = s3("https://s3.example", "b", true);
        assert_eq!(validate_s3(&bucket, "a/b/", &keys), Ok(()));
        assert!(validate_s3(&bucket, "a/b//", &keys).is_err());
        assert!(validate_s3(&bucket, "", &keys).is_err());
        assert!(validate_s3(&bucket, "/", &keys).is_err());
    }
}
