//! The `filter` mask, which Xray-core v26.11.9 registers in both
//! `finalmask.tcp` and `finalmask.udp`. It filters a server's incoming
//! connections and datagrams by source address; its client wrappers,
//! `WrapConnClient` and `WrapPacketConnClient`, return the connection
//! unchanged. A client therefore validates it as `Filter.Build` does and
//! keeps nothing of it.
use super::*;
use crate::go_lowercase;

/// The fields of Xray-core's `Filter`, in the order `Filter.Build` checks
/// them. No `surface` node lists them: that grammar fails closed on an
/// unknown field, which a filter ignores.
const FILTER_FIELDS: [&str; 2] = ["blockedSourceIPs", "allowedSourceIPs"];

/// Whether a `finalmask` entry is a filter, its type read as Xray-core
/// reads every mask type: lowercased.
pub(super) fn is_filter(mask: &Value) -> bool {
    mask.get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| go_lowercase(kind) == "filter")
}

impl Parser<'_> {
    /// A filter's settings, decoded into Xray-core's `Filter` as Go's JSON
    /// decoding does and checked as `Filter.Build` checks them: absent or
    /// null settings and lists are empty, field names match
    /// case-insensitively, and unknown fields are ignored. Nothing else
    /// about a filter reaches a client, so unlike the other masks it
    /// refuses no field of its own.
    pub(super) fn validate_filter_mask(&mut self, settings: Option<&Value>, path: &str) {
        let settings = match settings {
            None | Some(Value::Null) => return,
            Some(Value::Object(settings)) => settings,
            Some(_) => {
                self.error(path, "filter settings must be an object or null");
                return;
            }
        };
        for field in FILTER_FIELDS {
            // Go keeps the last spelling it decodes; with the document order
            // gone, every spelling present is checked.
            for (key, rules) in settings.iter().filter(|(key, _)| go_equal_fold(key, field)) {
                self.validate_filter_ip_rules(rules, &child_path(path, key), field);
            }
        }
    }

    /// A `[]string` of IP rules, each as `geodata.ParseIPRules` reads it.
    fn validate_filter_ip_rules(&mut self, rules: &Value, path: &str, field: &str) {
        let rules = match rules {
            Value::Null => return,
            Value::Array(rules) => rules,
            _ => {
                self.error(
                    path,
                    format!("field `{field}` must be an array of strings or null"),
                );
                return;
            }
        };
        for (index, rule) in rules.iter().enumerate() {
            let rule_path = format!("{path}[{index}]");
            // Go decodes a null item as the empty string.
            let rule = match rule {
                Value::Null => "",
                Value::String(rule) => rule.as_str(),
                _ => {
                    self.error(rule_path, format!("field `{field}` must hold strings"));
                    continue;
                }
            };
            if let Err(cause) = self.check_ip_rule(rule) {
                self.error(
                    rule_path,
                    format!(r#"invalid "{field}": illegal ip rule: {rule}: {cause}"#),
                );
            }
        }
    }

    /// One rule as `geodata.ParseIPRules` reads it, with its reason when it
    /// fails. `geoip:` names a code in `geoip.dat`, `ext:` and `ext-ip:` a
    /// file and a code, which must be there, as Xray-core's `checkFile`
    /// requires: no built-in `geoip:private` here. Anything else is a CIDR.
    fn check_ip_rule(&mut self, rule: &str) -> Result<(), String> {
        let (rule, _) = strip_inverse_prefix(rule);
        let (file, code) = if let Some(code) = rule.strip_prefix("geoip:") {
            ("geoip.dat", code)
        } else if let Some(spec) = rule
            .strip_prefix("ext:")
            .or_else(|| rule.strip_prefix("ext-ip:"))
        {
            spec.split_once(':').ok_or("syntax error")?
        } else {
            return check_custom_ip_rule(rule);
        };
        if file.is_empty() {
            return Err("empty file".to_owned());
        }
        let (code, _) = strip_inverse_prefix(code);
        if code.is_empty() {
            return Err("empty code".to_owned());
        }
        self.geodata_loader
            .check_code(file, code)
            .map_err(|error| error.to_string())
    }
}

/// `parseCIDR`: an address as `net.ParseAddress` reads it, then an optional
/// prefix length as `strconv.ParseUint(prefix, 10, 32)` reads it. An
/// IPv4-mapped IPv6 address is IPv4 there.
fn check_custom_ip_rule(rule: &str) -> Result<(), String> {
    let (address, prefix) = rule.split_once('/').unwrap_or((rule, ""));
    let max: u64 = match parse_xray_ip_address(address) {
        Some(IpAddr::V4(_)) => 32,
        Some(IpAddr::V6(address)) if address.to_ipv4_mapped().is_some() => 32,
        Some(IpAddr::V6(_)) => 128,
        None => return Err("unsupported address family".to_owned()),
    };
    if prefix.is_empty() {
        return Ok(());
    }
    let bits = prefix
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| prefix.parse::<u64>().ok())
        .flatten()
        .filter(|bits| *bits <= u64::from(u32::MAX))
        .ok_or_else(|| format!("invalid CIDR prefix length: {prefix}"))?;
    if bits > max {
        return Err(format!("CIDR prefix length {bits} exceeds max {max}"));
    }
    Ok(())
}

/// Go's `bytes.EqualFold` against an ASCII name, as Go's JSON decoding
/// matches field names: besides ASCII case, the Kelvin sign folds to `k`
/// and the long s to `s`.
fn go_equal_fold(text: &str, ascii: &str) -> bool {
    let mut chars = text.chars();
    let folds = ascii.bytes().all(|expected| match chars.next() {
        Some('\u{212A}') => expected.eq_ignore_ascii_case(&b'k'),
        Some('\u{017F}') => expected.eq_ignore_ascii_case(&b's'),
        Some(other) => u8::try_from(other).is_ok_and(|byte| byte.eq_ignore_ascii_case(&expected)),
        None => false,
    });
    folds && chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_rules_fail_as_parse_cidr_fails() {
        for ok in [
            "10.0.0.0/8",
            "10.0.0.0/",
            "10.0.0.0/08",
            "::ffff:192.0.2.1/24",
            "[2001:db8::]/32",
            " 192.0.2.1",
            "192.0.2.1 ",
            " 192.0.2.1/24",
            "::",
            "::1.2.3.4/128",
            "0.0.0.0/0",
        ] {
            assert_eq!(check_custom_ip_rule(ok), Ok(()), "{ok}");
        }
        for (rule, cause) in [
            ("10.0.0.0/33", "CIDR prefix length 33 exceeds max 32"),
            ("2001:db8::/129", "CIDR prefix length 129 exceeds max 128"),
            (
                "::ffff:192.0.2.1/96",
                "CIDR prefix length 96 exceeds max 32",
            ),
            (
                "10.0.0.0/4294967295",
                "CIDR prefix length 4294967295 exceeds max 32",
            ),
            (
                "10.0.0.0/4294967296",
                "invalid CIDR prefix length: 4294967296",
            ),
            ("10.0.0.0/+8", "invalid CIDR prefix length: +8"),
            ("10.0.0.0/-1", "invalid CIDR prefix length: -1"),
            ("192.0.2.1/ 24", "invalid CIDR prefix length:  24"),
            ("1.2.3.4/32/5", "invalid CIDR prefix length: 32/5"),
            ("", "unsupported address family"),
            ("example.com", "unsupported address family"),
            ("[2001:db8::/32]", "unsupported address family"),
            ("fe80::1%eth0", "unsupported address family"),
            ("01.2.3.4", "unsupported address family"),
            ("1.2.3", "unsupported address family"),
            ("GEOIP:cn", "unsupported address family"),
        ] {
            assert_eq!(check_custom_ip_rule(rule), Err(cause.to_owned()), "{rule}");
        }
    }

    #[test]
    fn field_names_fold_as_go_folds_them() {
        let field = "blockedSourceIPs";
        for key in [
            "blockedSourceIPs",
            "BlockedSourceIPs",
            "blockedsourceips",
            "BLOCKEDSOURCEIPS",
            "bloc\u{212A}edSourceIPs",
            "blocked\u{017F}ourceIP\u{017F}",
        ] {
            assert!(go_equal_fold(key, field), "{key}");
        }
        for key in [
            "blocked_source_ips",
            "blockedSourceIP",
            "blockedSourceIPss",
            "blockedSourceİPs",
            "",
        ] {
            assert!(!go_equal_fold(key, field), "{key}");
        }
    }
}
