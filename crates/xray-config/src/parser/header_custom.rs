//! The `header-custom` mask, read as Xray-core v26.10.31's
//! `HeaderCustomTCP.Build` reads it, and the `finalmask.tcp` array it sits in.
use super::*;
use crate::{
    go_lowercase, HeaderCustomArg, HeaderCustomExpr, HeaderCustomItem, HeaderCustomTcp,
    HeaderCustomUdp, TcpFragmentSettings,
};
use base64::Engine as _;

/// The most random bytes one item may ask for. Xray-core allocates whatever
/// `rand` says, which a large value turns into an out-of-memory crash.
pub(super) const MAX_HEADER_CUSTOM_RAND: i32 = 65_536;

/// The masks `finalmask.tcp` holds.
#[derive(Default)]
pub(super) struct TcpMasks {
    pub(super) fragment: Option<TcpFragmentSettings>,
    pub(super) header: Option<HeaderCustomTcp>,
    pub(super) sudoku: Option<crate::SudokuMask>,
    pub(super) xmc: Option<crate::XmcMask>,
}

impl Parser<'_> {
    /// `finalmask.tcp`: at most one `fragment`, one `header-custom` and one
    /// `sudoku` or `xmc` mask. The fragment and `header-custom` may stand
    /// together only with the fragment first: Xray-core fragments just the
    /// first write through it, which after `header-custom` is the handshake
    /// rather than the TLS ClientHello. Any number of filters may stand
    /// anywhere: Xray-core's client wraps nothing in them, and no TCP mask
    /// has to be outermost there.
    pub(super) fn parse_tcp_masks(&mut self, stream: Option<&Value>, index: usize) -> TcpMasks {
        let mut found = TcpMasks::default();
        let Some(raw) = stream
            .and_then(|stream| stream.get("finalmask"))
            .and_then(|finalmask| finalmask.get("tcp"))
            .filter(|raw| !raw.is_null())
        else {
            return found;
        };
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.tcp");
        let Some(masks) = raw.as_array() else {
            self.error(path, "finalmask.tcp must be an array or null");
            return found;
        };
        let mut fragment = None;
        let mut header = None;
        let mut sudoku = None;
        let mut xmc = None;
        for (i, mask) in masks.iter().enumerate() {
            let mask_path = format!("{path}[{i}]");
            self.reject_unknown_fields(mask, &mask_path, &surface::TCP_MASK_ENTRY);
            let settings = mask.get("settings").unwrap_or(&Value::Null);
            let kind = mask.get("type").and_then(Value::as_str).map(go_lowercase);
            let settings_path = format!("{mask_path}.settings");
            if kind.as_deref() == Some("filter") {
                self.validate_filter_mask(Some(settings), &settings_path);
                continue;
            }
            // Sudoku and xmc transform every byte the masks before them
            // write, so either goes last here, outermost on the wire.
            let last = match (&sudoku, &xmc) {
                (Some(_), _) => Some("sudoku"),
                (_, Some(_)) => Some("xmc"),
                _ => None,
            };
            if let Some(last) = last {
                self.error(&mask_path, format!("{last} must be the last TCP mask here"));
                continue;
            }
            match kind.as_deref() {
                Some("sudoku") => sudoku = Some(self.parse_sudoku(settings, &settings_path)),
                Some("xmc") => xmc = Some(self.parse_xmc(settings, &settings_path)),
                Some("fragment") if fragment.is_none() && header.is_none() => {
                    fragment = Some(self.parse_tcp_fragment(settings, &settings_path, false));
                }
                Some("fragment") if fragment.is_none() => self.error(
                    &mask_path,
                    "a fragment mask after header-custom would cut the header-custom handshake, which is not supported here; put it first",
                ),
                Some("header-custom") if header.is_none() => {
                    header = Some(self.parse_header_custom_tcp(settings, &settings_path));
                }
                _ => self.error(
                    &mask_path,
                    "only one fragment, one header-custom and one sudoku or xmc TCP mask are supported",
                ),
            }
        }
        found.fragment = fragment.flatten();
        found.header = header.flatten();
        found.sudoku = sudoku.flatten();
        found.xmc = xmc.flatten();
        found
    }

    /// `HeaderCustomTCP`: `clients`, `servers` and `errors`, each a list of
    /// item sequences. Absent or null settings read as `{}`.
    fn parse_header_custom_tcp(&mut self, settings: &Value, path: &str) -> Option<HeaderCustomTcp> {
        if settings.is_null() {
            return Some(HeaderCustomTcp::default());
        }
        if !settings.is_object() {
            self.error(path, "header-custom settings must be an object or null");
            return None;
        }
        self.reject_unknown_fields(settings, path, &surface::HEADER_CUSTOM_TCP);
        let mut valid = true;
        let mut sequences = |key: &str| {
            let key_path = format!("{path}.{key}");
            match settings.get(key) {
                None | Some(Value::Null) => Some(Vec::new()),
                Some(Value::Array(sequences)) => sequences
                    .iter()
                    .enumerate()
                    .map(|(i, sequence)| {
                        self.parse_header_custom_items(sequence, &format!("{key_path}[{i}]"), true)
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .collect::<Option<Vec<_>>>(),
                Some(_) => {
                    self.error(key_path, "header-custom sequences must be an array or null");
                    None
                }
            }
        };
        let clients = sequences("clients");
        let servers = sequences("servers");
        let errors = sequences("errors");
        valid &= clients.is_some() && servers.is_some() && errors.is_some();
        valid.then(|| HeaderCustomTcp {
            clients: clients.unwrap_or_default(),
            servers: servers.unwrap_or_default(),
            errors: errors.unwrap_or_default(),
        })
    }

    /// The `header-custom` entry of `finalmask.udp`, as `HeaderCustomUDP.Build`
    /// reads it, with its place among the noise and Salamander masks. The
    /// stream checks its carrier.
    pub(super) fn parse_udp_header_custom(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<HeaderCustomUdp> {
        let masks = stream?.pointer("/finalmask/udp")?.as_array()?;
        let position = |name: &str| {
            masks.iter().position(|mask| {
                mask.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| go_lowercase(kind) == name)
            })
        };
        let i = position("header-custom")?;
        let mask = &masks[i];
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp[{i}]");
        let settings_path = format!("{path}.settings");
        let settings = match mask.get("settings") {
            None | Some(Value::Null) => &Value::Null,
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(
                    settings_path,
                    "header-custom settings must be an object or null",
                );
                return None;
            }
        };
        self.reject_unknown_fields(settings, &settings_path, &surface::HEADER_CUSTOM_UDP);
        let mode = self.nullable_string_at(settings, "mode", format!("{settings_path}.mode"))?;
        // A switch on the exact string there.
        let standalone = match mode {
            "" | "prefix" => false,
            "standalone" => true,
            _ => {
                self.error(format!("{settings_path}.mode"), "unknown udp mode");
                return None;
            }
        };
        let client = self.parse_header_custom_items(
            settings.get("client").unwrap_or(&Value::Null),
            &format!("{settings_path}.client"),
            false,
        );
        let server = self.parse_header_custom_items(
            settings.get("server").unwrap_or(&Value::Null),
            &format!("{settings_path}.server"),
            false,
        );
        Some(HeaderCustomUdp {
            standalone,
            client: client?,
            server: server?,
            before_salamander: position("salamander").is_some_and(|s| i < s),
            before_noise: position("noise").is_some_and(|n| i < n),
        })
    }

    /// One sequence: an array of items, or null for none.
    pub(super) fn parse_header_custom_items(
        &mut self,
        value: &Value,
        path: &str,
        tcp: bool,
    ) -> Option<Vec<HeaderCustomItem>> {
        match value {
            Value::Null => Some(Vec::new()),
            Value::Array(items) => items
                .iter()
                .enumerate()
                .map(|(i, item)| self.parse_header_custom_item(item, &format!("{path}[{i}]"), tcp))
                .collect::<Vec<_>>()
                .into_iter()
                .collect(),
            _ => {
                self.error(path, "a header-custom sequence must be an array or null");
                None
            }
        }
    }

    /// One `TCPItem` or `UDPItem`, checked as `validateCustomItemSpec` and
    /// the build loop check it.
    fn parse_header_custom_item(
        &mut self,
        item: &Value,
        path: &str,
        tcp: bool,
    ) -> Option<HeaderCustomItem> {
        // Go leaves a null element as the zero item, which has no kind.
        let empty = Value::Object(Default::default());
        let item = if item.is_null() { &empty } else { item };
        if !item.is_object() {
            self.error(path, "a header-custom item must be an object");
            return None;
        }
        self.reject_unknown_fields(
            item,
            path,
            if tcp {
                &surface::HEADER_CUSTOM_TCP_ITEM
            } else {
                &surface::HEADER_CUSTOM_UDP_ITEM
            },
        );
        let capture = self.nullable_string_at(item, "capture", format!("{path}.capture"));
        let reuse = self.nullable_string_at(item, "reuse", format!("{path}.reuse"));
        let kind = self.nullable_string_at(item, "type", format!("{path}.type"));
        let rand = match item.get("rand") {
            None | Some(Value::Null) => Some(0),
            Some(raw) => match raw.as_i64().and_then(|value| i32::try_from(value).ok()) {
                Some(value) => Some(value),
                None => {
                    self.error(format!("{path}.rand"), "field `rand` must fit in i32");
                    None
                }
            },
        };
        let delay = if tcp {
            self.go_int32_range(item.get("delay"), &format!("{path}.delay"))
        } else {
            Some((0, 0))
        };
        let rand_range = match item.get("randRange") {
            None | Some(Value::Null) => Some((0, 255)),
            Some(raw) => self.go_int32_range(Some(raw), &format!("{path}.randRange")),
        };
        // `transform` is a pointer: null is no transform.
        let transform = match item.get("transform") {
            None | Some(Value::Null) => Some(None),
            Some(raw) => self
                .parse_header_custom_transform(raw, &format!("{path}.transform"))
                .map(Some),
        };
        let (capture, reuse, kind, rand, delay, rand_range, transform) = (
            capture?,
            reuse?,
            kind?,
            rand?,
            delay?,
            rand_range?,
            transform?,
        );
        let mut valid = true;
        for (key, name) in [("capture", capture), ("reuse", reuse)] {
            if !is_custom_var_name(name) {
                self.error(format!("{path}.{key}"), "invalid variable name");
                valid = false;
            }
        }
        // A present `packet` counts as one kind even when it is null, as a
        // non-empty `json.RawMessage` does there.
        let kinds = usize::from(item.get("packet").is_some())
            + usize::from(rand > 0)
            + usize::from(!reuse.is_empty())
            + usize::from(transform.is_some());
        if kinds > 1 || (kinds == 0 && !capture.is_empty()) {
            self.error(path, "exactly one item kind must be set");
            valid = false;
        }
        if rand > MAX_HEADER_CUSTOM_RAND {
            self.error(
                format!("{path}.rand"),
                format!("rand is at most {MAX_HEADER_CUSTOM_RAND} bytes here"),
            );
            valid = false;
        }
        if rand_range.0 < 0 || rand_range.1 > 255 {
            self.error(format!("{path}.randRange"), "invalid randRange");
            valid = false;
        }
        let packet = match xray_byte_slice(item.get("packet"), kind) {
            Some(packet) => packet,
            None => {
                self.error(
                    format!("{path}.packet"),
                    "invalid packet or type (array, str, hex, base64)",
                );
                valid = false;
                Vec::new()
            }
        };
        valid.then(|| HeaderCustomItem {
            delay,
            rand,
            rand_range,
            packet,
            capture: capture.to_owned(),
            reuse: reuse.to_owned(),
            transform,
        })
    }

    /// A `CustomTransform`: a nonempty `op` over nonempty `args`.
    fn parse_header_custom_transform(
        &mut self,
        raw: &Value,
        path: &str,
    ) -> Option<HeaderCustomExpr> {
        if !raw.is_object() {
            self.error(path, "a header-custom transform must be an object or null");
            return None;
        }
        self.reject_unknown_fields(raw, path, &surface::HEADER_CUSTOM_TRANSFORM);
        let op = self.nullable_string_at(raw, "op", format!("{path}.op"))?;
        let args = match raw.get("args") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(args)) => args
                .iter()
                .enumerate()
                .map(|(i, arg)| self.parse_header_custom_arg(arg, &format!("{path}.args[{i}]")))
                .collect::<Vec<_>>()
                .into_iter()
                .collect::<Option<Vec<_>>>()?,
            Some(_) => {
                self.error(
                    format!("{path}.args"),
                    "transform args must be an array or null",
                );
                return None;
            }
        };
        if op.is_empty() {
            self.error(format!("{path}.op"), "transform op is required");
            return None;
        }
        if args.is_empty() {
            self.error(format!("{path}.args"), "transform args are required");
            return None;
        }
        Some(HeaderCustomExpr {
            op: op.to_owned(),
            args,
        })
    }

    /// A `CustomTransformArg`: exactly one of `bytes`, `u64`, `reuse`,
    /// `metadata` and `transform`.
    fn parse_header_custom_arg(&mut self, raw: &Value, path: &str) -> Option<HeaderCustomArg> {
        if !raw.is_object() {
            self.error(path, "a transform arg must be an object");
            return None;
        }
        self.reject_unknown_fields(raw, path, &surface::HEADER_CUSTOM_ARG);
        let kind = self.nullable_string_at(raw, "type", format!("{path}.type"));
        let reuse = self.nullable_string_at(raw, "reuse", format!("{path}.reuse"));
        let metadata = self.nullable_string_at(raw, "metadata", format!("{path}.metadata"));
        let u64 = match raw.get("u64") {
            None | Some(Value::Null) => Some(None),
            Some(value) => match value.as_u64() {
                Some(value) => Some(Some(value)),
                None => {
                    self.error(format!("{path}.u64"), "field `u64` must fit in u64");
                    None
                }
            },
        };
        let transform = match raw.get("transform") {
            None | Some(Value::Null) => Some(None),
            Some(value) => self
                .parse_header_custom_transform(value, &format!("{path}.transform"))
                .map(Some),
        };
        let (kind, reuse, metadata, u64, transform) = (kind?, reuse?, metadata?, u64?, transform?);
        let kinds = usize::from(raw.get("bytes").is_some())
            + usize::from(u64.is_some())
            + usize::from(!reuse.is_empty())
            + usize::from(!metadata.is_empty())
            + usize::from(transform.is_some());
        if kinds != 1 {
            self.error(path, "transform arg must set exactly one value");
            return None;
        }
        if raw.get("bytes").is_some() {
            return match xray_byte_slice(raw.get("bytes"), kind) {
                Some(bytes) => Some(HeaderCustomArg::Bytes(bytes)),
                None => {
                    self.error(
                        format!("{path}.bytes"),
                        "invalid bytes or type (array, str, hex, base64)",
                    );
                    None
                }
            };
        }
        if let Some(value) = u64 {
            return Some(HeaderCustomArg::U64(value));
        }
        if !reuse.is_empty() {
            if !is_custom_var_name(reuse) {
                self.error(format!("{path}.reuse"), "invalid variable name");
                return None;
            }
            return Some(HeaderCustomArg::Reuse(reuse.to_owned()));
        }
        if !metadata.is_empty() {
            return Some(HeaderCustomArg::Metadata(metadata.to_owned()));
        }
        transform.map(HeaderCustomArg::Transform)
    }

    /// Go's `Int32Range`: a JSON integer, or a range string such as `"-5-10"`;
    /// null is zero, and the two ends come back in order.
    fn go_int32_range(&mut self, raw: Option<&Value>, path: &str) -> Option<(i32, i32)> {
        let pair = match raw {
            None | Some(Value::Null) => Some((0, 0)),
            Some(Value::String(text)) => parse_xhttp_range_string(text),
            Some(value) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(|value| (value, value)),
        };
        match pair {
            Some((left, right)) => Some((left.min(right), left.max(right))),
            None => {
                self.error(
                    path,
                    "invalid integer range, expected either string of form \"1-2\" or plain integer",
                );
                None
            }
        }
    }
}

/// Xray-core's `customVarNamePattern`: empty, or `[A-Za-z_][A-Za-z0-9_]*`.
fn is_custom_var_name(name: &str) -> bool {
    let mut characters = name.chars();
    match characters.next() {
        None => true,
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {
            characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        Some(_) => false,
    }
}

/// Xray-core's `PraseByteSlice`: `kind` is `array` or empty (a JSON byte
/// array, or a string that Go's `[]byte` decoding reads as base64), `str`,
/// `hex` or `base64`, case-insensitive. Null is empty. Absent is empty only
/// for an array: the other kinds unmarshal nothing there, which fails.
pub(super) fn xray_byte_slice(packet: Option<&Value>, kind: &str) -> Option<Vec<u8>> {
    let base64 = |text: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text.replace(['\r', '\n'], ""))
            .ok()
    };
    let kind = kind.to_ascii_lowercase();
    if matches!(kind.as_str(), "" | "array") {
        return match packet.unwrap_or(&Value::Null) {
            Value::Null => Some(Vec::new()),
            Value::Array(items) => items
                .iter()
                .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect(),
            Value::String(text) => base64(text),
            _ => None,
        };
    }
    let text = match packet? {
        Value::Null => "",
        Value::String(text) => text,
        _ => return None,
    };
    match kind.as_str() {
        "str" => Some(text.as_bytes().to_vec()),
        "base64" => base64(text),
        "hex" => {
            if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
                .collect()
        }
        _ => None,
    }
}
