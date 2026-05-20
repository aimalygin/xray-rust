use std::net::IpAddr;

use serde_json::Value;
use uuid::Uuid;

use crate::{
    CoreConfig, Diagnostic, InboundConfig, InboundProtocol, Network, OutboundConfig,
    OutboundSettings, RealitySettings, RealityShortId, StreamSecurity, StreamSettings, TargetAddr,
    TlsSettings, VlessOutboundSettings, VlessUser,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    pub config: CoreConfig,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("xray config parse failed")]
pub struct ConfigParseError {
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse_xray_json(raw: &str) -> Result<ParsedConfig, ConfigParseError> {
    let value = serde_json::from_str::<Value>(raw).map_err(|err| ConfigParseError {
        diagnostics: vec![Diagnostic::error("$", err.to_string())],
    })?;

    let mut parser = Parser {
        root: &value,
        diagnostics: Vec::new(),
    };
    let config = parser.parse_config();

    if parser
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == crate::DiagnosticSeverity::Error)
    {
        Err(ConfigParseError {
            diagnostics: parser.diagnostics,
        })
    } else {
        Ok(ParsedConfig {
            config,
            diagnostics: parser.diagnostics,
        })
    }
}

struct Parser<'a> {
    root: &'a Value,
    diagnostics: Vec<Diagnostic>,
}

impl Parser<'_> {
    fn parse_config(&mut self) -> CoreConfig {
        CoreConfig {
            inbounds: self.parse_inbounds(),
            outbounds: self.parse_outbounds(),
            default_outbound_tag: None,
        }
    }

    fn parse_inbounds(&mut self) -> Vec<InboundConfig> {
        let Some(inbounds) = self.root.get("inbounds").and_then(Value::as_array) else {
            return Vec::new();
        };

        inbounds
            .iter()
            .enumerate()
            .filter_map(|(index, inbound)| self.parse_inbound(inbound, index))
            .collect()
    }

    fn parse_inbound(&mut self, inbound: &Value, index: usize) -> Option<InboundConfig> {
        let protocol_path = format!("$.inbounds[{index}].protocol");
        let protocol = match self.string_at(inbound, "protocol") {
            Some("socks") => InboundProtocol::Socks,
            Some("http") => InboundProtocol::Http,
            Some("tun") => InboundProtocol::Tun,
            Some(protocol) => {
                self.error(
                    protocol_path,
                    format!("unsupported inbound protocol `{protocol}`"),
                );
                return None;
            }
            None => {
                self.error(protocol_path, "missing inbound protocol");
                return None;
            }
        };

        let port = self
            .u16_at(inbound, "port", format!("$.inbounds[{index}].port"))
            .unwrap_or(0);

        Some(InboundConfig {
            tag: self.string_at(inbound, "tag").map(ToOwned::to_owned),
            protocol,
            listen: self
                .string_at(inbound, "listen")
                .unwrap_or("127.0.0.1")
                .to_owned(),
            port,
        })
    }

    fn parse_outbounds(&mut self) -> Vec<OutboundConfig> {
        let Some(outbounds) = self.root.get("outbounds").and_then(Value::as_array) else {
            return Vec::new();
        };

        outbounds
            .iter()
            .enumerate()
            .filter_map(|(index, outbound)| self.parse_outbound(outbound, index))
            .collect()
    }

    fn parse_outbound(&mut self, outbound: &Value, index: usize) -> Option<OutboundConfig> {
        let protocol_path = format!("$.outbounds[{index}].protocol");
        match self.string_at(outbound, "protocol") {
            Some("vless") => {}
            Some(protocol) => {
                self.error(
                    protocol_path,
                    format!("unsupported outbound protocol `{protocol}`"),
                );
                return None;
            }
            None => {
                self.error(protocol_path, "missing outbound protocol");
                return None;
            }
        }

        let settings = self.parse_vless_settings(outbound, index)?;
        let stream = self.parse_stream_settings(outbound, index)?;

        Some(OutboundConfig {
            tag: self.string_at(outbound, "tag").map(ToOwned::to_owned),
            stream,
            settings: OutboundSettings::Vless(settings),
        })
    }

    fn parse_vless_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<VlessOutboundSettings> {
        let vnext_array_path = format!("$.outbounds[{index}].settings.vnext");
        let Some(vnext_array) = outbound
            .get("settings")
            .and_then(|settings| settings.get("vnext"))
            .and_then(Value::as_array)
        else {
            self.error(vnext_array_path, "missing vless vnext servers");
            return None;
        };
        if vnext_array.len() > 1 {
            self.error(
                vnext_array_path,
                "multiple vless vnext servers are unsupported",
            );
            return None;
        }

        let vnext_path = format!("$.outbounds[{index}].settings.vnext[0]");
        let Some(vnext) = vnext_array.first() else {
            self.error(vnext_path, "missing vless vnext server");
            return None;
        };

        let address_path = format!("$.outbounds[{index}].settings.vnext[0].address");
        let Some(address) = self.string_at(vnext, "address") else {
            self.error(address_path, "missing vless server address");
            return None;
        };
        if address.is_empty() {
            self.error(address_path, "vless server address must not be empty");
            return None;
        }
        let server = address
            .parse::<IpAddr>()
            .map_or_else(|_| TargetAddr::Domain(address.to_owned()), TargetAddr::Ip);

        let port_path = format!("$.outbounds[{index}].settings.vnext[0].port");
        let port = self.u16_at(vnext, "port", port_path.clone())?;
        if port == 0 {
            self.error(port_path, "vless server port must not be 0");
            return None;
        }

        let users = self.parse_vless_users(vnext, index)?;

        Some(VlessOutboundSettings {
            server,
            port,
            users,
        })
    }

    fn parse_vless_users(
        &mut self,
        vnext: &Value,
        outbound_index: usize,
    ) -> Option<Vec<VlessUser>> {
        let users_path = format!("$.outbounds[{outbound_index}].settings.vnext[0].users");
        let Some(users) = vnext.get("users").and_then(Value::as_array) else {
            self.error(users_path, "vless users must be a non-empty array");
            return None;
        };
        if users.is_empty() {
            self.error(users_path, "vless users must be a non-empty array");
            return None;
        }

        let parsed_users = users
            .iter()
            .enumerate()
            .filter_map(|(user_index, user)| {
                self.parse_vless_user(user, outbound_index, user_index)
            })
            .collect::<Vec<_>>();

        if parsed_users.is_empty() {
            None
        } else {
            Some(parsed_users)
        }
    }

    fn parse_vless_user(
        &mut self,
        user: &Value,
        outbound_index: usize,
        user_index: usize,
    ) -> Option<VlessUser> {
        let id_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].id");
        let Some(id) = self.string_at(user, "id") else {
            self.error(id_path, "missing vless user id");
            return None;
        };
        let id = match Uuid::parse_str(id) {
            Ok(id) => id,
            Err(err) => {
                self.error(id_path, err.to_string());
                return None;
            }
        };

        let encryption_path = format!(
            "$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].encryption"
        );
        let encryption = self.string_at(user, "encryption").unwrap_or("none");
        if encryption != "none" {
            self.error(
                encryption_path,
                format!("unsupported vless user encryption `{encryption}`"),
            );
            return None;
        }

        let flow_path =
            format!("$.outbounds[{outbound_index}].settings.vnext[0].users[{user_index}].flow");
        let flow = match self.string_at(user, "flow") {
            Some("") | None => None,
            Some("xtls-rprx-vision") => Some("xtls-rprx-vision".to_owned()),
            Some(flow) => {
                self.error(flow_path, format!("unsupported vless user flow `{flow}`"));
                return None;
            }
        };

        Some(VlessUser {
            id,
            encryption: encryption.to_owned(),
            flow,
        })
    }

    fn parse_stream_settings(&mut self, outbound: &Value, index: usize) -> Option<StreamSettings> {
        let stream = outbound.get("streamSettings");
        let network = self.parse_network(stream, index)?;
        let security = self.parse_security(stream, index)?;

        Some(StreamSettings { network, security })
    }

    fn parse_network(&mut self, stream: Option<&Value>, index: usize) -> Option<Network> {
        let network_path = format!("$.outbounds[{index}].streamSettings.network");
        match stream
            .and_then(|stream| stream.get("network"))
            .and_then(Value::as_str)
            .unwrap_or("tcp")
        {
            "tcp" => Some(Network::Tcp),
            network => {
                self.error(
                    network_path,
                    format!("unsupported stream network `{network}`"),
                );
                None
            }
        }
    }

    fn parse_security(&mut self, stream: Option<&Value>, index: usize) -> Option<StreamSecurity> {
        let security_path = format!("$.outbounds[{index}].streamSettings.security");
        match stream
            .and_then(|stream| stream.get("security"))
            .and_then(Value::as_str)
            .unwrap_or("none")
        {
            "none" => Some(StreamSecurity::None),
            "tls" => Some(StreamSecurity::Tls(TlsSettings {
                server_name: stream
                    .and_then(|stream| stream.get("tlsSettings"))
                    .and_then(|settings| self.string_at(settings, "serverName"))
                    .map(ToOwned::to_owned),
                fingerprint: stream
                    .and_then(|stream| stream.get("tlsSettings"))
                    .and_then(|settings| self.string_at(settings, "fingerprint"))
                    .map(ToOwned::to_owned),
            })),
            "reality" => self
                .parse_reality_settings(stream, index)
                .map(StreamSecurity::Reality),
            security => {
                self.error(
                    security_path,
                    format!("unsupported stream security `{security}`"),
                );
                None
            }
        }
    }

    fn parse_reality_settings(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<RealitySettings> {
        let settings = stream.and_then(|stream| stream.get("realitySettings"));
        let base_path = format!("$.outbounds[{index}].streamSettings.realitySettings");
        let public_key_path = format!("{base_path}.publicKey");
        let public_key = self.parse_reality_public_key(settings, &public_key_path)?;
        let short_id = self.parse_reality_short_id(settings, &format!("{base_path}.shortId"))?;
        let server_name_path = format!("{base_path}.serverName");
        let Some(server_name) =
            settings.and_then(|settings| self.string_at(settings, "serverName"))
        else {
            self.error(server_name_path, "missing reality server name");
            return None;
        };
        if server_name.is_empty() {
            self.error(server_name_path, "reality server name must not be empty");
            return None;
        }

        let fingerprint_path = format!("{base_path}.fingerprint");
        let Some(fingerprint) =
            settings.and_then(|settings| self.string_at(settings, "fingerprint"))
        else {
            self.error(fingerprint_path, "missing reality fingerprint");
            return None;
        };
        if fingerprint != "chrome" {
            self.error(
                fingerprint_path,
                format!("unsupported reality fingerprint `{fingerprint}`"),
            );
            return None;
        }

        Some(RealitySettings {
            server_name: server_name.to_owned(),
            fingerprint: fingerprint.to_owned(),
            public_key,
            short_id,
            spider_x: settings
                .and_then(|settings| self.string_at(settings, "spiderX"))
                .unwrap_or_default()
                .to_owned(),
        })
    }

    fn parse_reality_public_key(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<[u8; 32]> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("publicKey"))
            .and_then(Value::as_str)
        else {
            self.error(path, "missing reality public key");
            return None;
        };
        let bytes = match decode_base64url_no_padding(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(public_key) => Some(public_key),
            Err(_) => {
                self.error(path, "reality public key must decode to 32 bytes");
                None
            }
        }
    }

    fn parse_reality_short_id(
        &mut self,
        settings: Option<&Value>,
        path: &str,
    ) -> Option<RealityShortId> {
        let Some(encoded) = settings
            .and_then(|settings| settings.get("shortId"))
            .and_then(Value::as_str)
        else {
            self.error(path, "missing reality short id");
            return None;
        };
        let bytes = match decode_hex(encoded) {
            Ok(bytes) => bytes,
            Err(message) => {
                self.error(path, message);
                return None;
            }
        };
        match RealityShortId::try_from_slice(&bytes) {
            Ok(short_id) => Some(short_id),
            Err(err) => {
                self.error(path, err.to_string());
                None
            }
        }
    }

    fn string_at<'a>(&self, value: &'a Value, key: &str) -> Option<&'a str> {
        value.get(key).and_then(Value::as_str)
    }

    fn u16_at(&mut self, value: &Value, key: &str, path: String) -> Option<u16> {
        let Some(raw) = value.get(key).and_then(Value::as_u64) else {
            self.error(path, format!("missing numeric field `{key}`"));
            return None;
        };
        match u16::try_from(raw) {
            Ok(port) => Some(port),
            Err(_) => {
                self.error(path, format!("field `{key}` must fit in u16"));
                None
            }
        }
    }

    fn error(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic::error(path, message));
    }
}

fn decode_base64url_no_padding(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.contains('=') {
        return Err("base64url value must not be padded".to_owned());
    }

    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0;

    for byte in encoded.bytes() {
        chunk[chunk_len] = base64url_value(byte)?;
        chunk_len += 1;

        if chunk_len == 4 {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
            output.push((chunk[2] << 6) | chunk[3]);
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => {}
        1 => return Err("invalid base64url length".to_owned()),
        2 => {
            if chunk[1] & 0x0f != 0 {
                return Err("invalid base64url tail bits".to_owned());
            }
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        3 => {
            if chunk[2] & 0x03 != 0 {
                return Err("invalid base64url tail bits".to_owned());
            }
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        _ => unreachable!(),
    }

    Ok(output)
}

fn base64url_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err("invalid base64url character".to_owned()),
    }
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    let bytes = encoded.as_bytes();
    let chunks = bytes.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err("hex value must have an even length".to_owned());
    }

    chunks
        .map(|chunk| Ok((hex_value(chunk[0])? << 4) | hex_value(chunk[1])?))
        .collect()
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_owned()),
    }
}
