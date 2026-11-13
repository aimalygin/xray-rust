//! `burstObservatory`, as `infra/conf/observatory.go` and
//! `app/observatory/burst/healthping.go` of Xray-core v26.11.9 read it.

use std::time::Duration;

use serde_json::Value;

use super::{parse_xray_duration, Parser, MAX_OBSERVATORY_SUBJECT_SELECTORS};
use crate::model::{
    BurstObservatoryConfig, BurstPingConfig, DEFAULT_BURST_OBSERVATORY_DESTINATION,
    DEFAULT_BURST_OBSERVATORY_HTTP_METHOD, DEFAULT_BURST_OBSERVATORY_INTERVAL,
    DEFAULT_BURST_OBSERVATORY_SAMPLING, DEFAULT_BURST_OBSERVATORY_TIMEOUT,
    MAX_BURST_OBSERVATORY_INTERVAL, MAX_BURST_OBSERVATORY_SAMPLING, MAX_BURST_OBSERVATORY_TIMEOUT,
    MIN_BURST_OBSERVATORY_INTERVAL,
};
use crate::surface;

const PATH: &str = "$.burstObservatory";

/// A Go `time.ParseDuration` string, which may carry a sign or be a bare `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignedDuration {
    Negative,
    NonNegative(Duration),
}

fn parse_signed_duration(raw: &str) -> Option<SignedDuration> {
    let (negative, magnitude) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let magnitude = if magnitude == "0" {
        Duration::ZERO
    } else {
        parse_xray_duration(magnitude)?
    };
    Some(if negative && !magnitude.is_zero() {
        SignedDuration::Negative
    } else {
        SignedDuration::NonNegative(magnitude)
    })
}

/// Go's `net/http` accepts a method made of RFC 7230 token characters.
fn is_http_token(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

impl Parser<'_> {
    pub(super) fn parse_burst_observatory(&mut self) -> Option<BurstObservatoryConfig> {
        let observatory = self.root.get("burstObservatory")?;
        if observatory.is_null() {
            return None;
        }
        if !observatory.is_object() {
            self.error(PATH, "burstObservatory must be an object or null");
            return None;
        }
        self.reject_unknown_fields(observatory, PATH, &surface::BURST_OBSERVATORY);

        let subject_selectors =
            self.parse_subject_selectors(observatory, PATH, "burstObservatory")?;
        let ping_path = format!("{PATH}.pingConfig");
        let ping = match observatory.get("pingConfig") {
            Some(ping @ Value::Object(_)) => self.parse_burst_ping_config(ping, &ping_path)?,
            None | Some(Value::Null) => {
                self.error(ping_path, "BurstObservatory requires a valid pingConfig");
                return None;
            }
            Some(_) => {
                self.error(ping_path, "burstObservatory pingConfig must be an object");
                return None;
            }
        };
        if self
            .root
            .get("observatory")
            .is_some_and(|classic| !classic.is_null())
        {
            self.warning(
                PATH,
                "observatory is also present and drives outbound selection, as in Xray-core; burstObservatory is not run",
            );
        }

        Some(BurstObservatoryConfig {
            subject_selectors,
            ping,
        })
    }

    /// `subjectSelector` of either observatory: outbound tag prefixes.
    pub(super) fn parse_subject_selectors(
        &mut self,
        observatory: &Value,
        path: &str,
        owner: &str,
    ) -> Option<Vec<String>> {
        let values = match observatory.get("subjectSelector") {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(values)) => values,
            Some(_) => {
                self.error(
                    format!("{path}.subjectSelector"),
                    format!("{owner} subjectSelector must be an array"),
                );
                return None;
            }
        };
        if values.len() > MAX_OBSERVATORY_SUBJECT_SELECTORS {
            self.error(
                format!("{path}.subjectSelector"),
                format!(
                    "{owner} contains {} subject selectors; maximum supported per configuration is {MAX_OBSERVATORY_SUBJECT_SELECTORS}",
                    values.len()
                ),
            );
            return None;
        }
        let mut selectors = Vec::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            let Some(value) = value.as_str() else {
                self.error(
                    format!("{path}.subjectSelector[{index}]"),
                    format!("{owner} subject selector must be a string"),
                );
                return None;
            };
            selectors.push(value.to_owned());
        }
        Some(selectors)
    }

    fn parse_burst_ping_config(&mut self, ping: &Value, path: &str) -> Option<BurstPingConfig> {
        self.reject_unknown_fields(ping, path, &surface::BURST_PING_CONFIG);

        let destination = self.burst_ping_string(ping, path, "destination")?;
        let connectivity = self.burst_ping_string(ping, path, "connectivity")?;
        let http_method = match ping.get("httpMethod") {
            None | Some(Value::Null) => DEFAULT_BURST_OBSERVATORY_HTTP_METHOD.to_owned(),
            Some(Value::String(method)) if method.is_empty() => {
                DEFAULT_BURST_OBSERVATORY_HTTP_METHOD.to_owned()
            }
            // Xray-core trims a nonempty method, and `net/http` reads the
            // empty one that whitespace leaves as GET.
            Some(Value::String(method)) if method.trim().is_empty() => "GET".to_owned(),
            Some(Value::String(method)) if is_http_token(method.trim()) => method.trim().to_owned(),
            Some(Value::String(_)) => {
                self.error(
                    format!("{path}.httpMethod"),
                    "burstObservatory httpMethod must be an HTTP method token",
                );
                return None;
            }
            Some(_) => {
                self.error(
                    format!("{path}.httpMethod"),
                    "burstObservatory httpMethod must be a string or null",
                );
                return None;
            }
        };
        let interval = match self.burst_ping_duration(ping, path, "interval")? {
            None => DEFAULT_BURST_OBSERVATORY_INTERVAL,
            Some(SignedDuration::NonNegative(interval)) if interval.is_zero() => {
                DEFAULT_BURST_OBSERVATORY_INTERVAL
            }
            Some(SignedDuration::NonNegative(interval))
                if interval > MAX_BURST_OBSERVATORY_INTERVAL =>
            {
                self.warning(
                    format!("{path}.interval"),
                    "burstObservatory interval is too large, 24h is applied",
                );
                MAX_BURST_OBSERVATORY_INTERVAL
            }
            Some(SignedDuration::NonNegative(interval))
                if interval >= MIN_BURST_OBSERVATORY_INTERVAL =>
            {
                interval
            }
            Some(_) => {
                self.warning(
                    format!("{path}.interval"),
                    "health check interval is too small, 10s is applied",
                );
                MIN_BURST_OBSERVATORY_INTERVAL
            }
        };
        let timeout = match self.burst_ping_duration(ping, path, "timeout")? {
            None | Some(SignedDuration::Negative) => DEFAULT_BURST_OBSERVATORY_TIMEOUT,
            Some(SignedDuration::NonNegative(timeout)) if timeout.is_zero() => {
                DEFAULT_BURST_OBSERVATORY_TIMEOUT
            }
            Some(SignedDuration::NonNegative(timeout))
                if timeout > MAX_BURST_OBSERVATORY_TIMEOUT =>
            {
                self.warning(
                    format!("{path}.timeout"),
                    "burstObservatory timeout is too large, 60s is applied",
                );
                MAX_BURST_OBSERVATORY_TIMEOUT
            }
            Some(SignedDuration::NonNegative(timeout)) => timeout,
        };
        let sampling = match ping.get("sampling") {
            None | Some(Value::Null) => DEFAULT_BURST_OBSERVATORY_SAMPLING,
            Some(Value::Number(sampling)) if sampling.is_i64() || sampling.is_u64() => {
                match sampling.as_i64() {
                    Some(sampling) if sampling <= 0 => DEFAULT_BURST_OBSERVATORY_SAMPLING,
                    Some(sampling) if sampling <= i64::from(MAX_BURST_OBSERVATORY_SAMPLING) => {
                        u32::try_from(sampling).unwrap_or(MAX_BURST_OBSERVATORY_SAMPLING)
                    }
                    _ => {
                        self.warning(
                            format!("{path}.sampling"),
                            format!(
                                "burstObservatory sampling is too large, {MAX_BURST_OBSERVATORY_SAMPLING} is applied"
                            ),
                        );
                        MAX_BURST_OBSERVATORY_SAMPLING
                    }
                }
            }
            Some(_) => {
                self.error(
                    format!("{path}.sampling"),
                    "burstObservatory sampling must be an integer or null",
                );
                return None;
            }
        };

        Some(BurstPingConfig {
            destination: if destination.is_empty() {
                DEFAULT_BURST_OBSERVATORY_DESTINATION.to_owned()
            } else {
                destination
            },
            connectivity: (!connectivity.is_empty()).then_some(connectivity),
            interval,
            sampling,
            timeout,
            http_method,
        })
    }

    /// A URL field, trimmed as Xray-core trims it; absent and null are empty.
    fn burst_ping_string(&mut self, ping: &Value, path: &str, key: &str) -> Option<String> {
        match ping.get(key) {
            None | Some(Value::Null) => Some(String::new()),
            Some(Value::String(value)) => Some(value.trim().to_owned()),
            Some(_) => {
                self.error(
                    format!("{path}.{key}"),
                    format!("burstObservatory {key} must be a string or null"),
                );
                None
            }
        }
    }

    /// The outer `None` is a reported error, the inner one an absent field.
    fn burst_ping_duration(
        &mut self,
        ping: &Value,
        path: &str,
        key: &str,
    ) -> Option<Option<SignedDuration>> {
        match ping.get(key) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(value)) => match parse_signed_duration(value) {
                Some(duration) => Some(Some(duration)),
                None => {
                    self.error(
                        format!("{path}.{key}"),
                        format!("burstObservatory {key} must be a valid Xray duration string"),
                    );
                    None
                }
            },
            Some(_) => {
                self.error(
                    format!("{path}.{key}"),
                    format!("burstObservatory {key} must be a duration string or null"),
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_durations_follow_go_parse_duration() {
        assert_eq!(parse_signed_duration("-5s"), Some(SignedDuration::Negative));
        assert_eq!(
            parse_signed_duration("+1m30s"),
            Some(SignedDuration::NonNegative(Duration::from_secs(90)))
        );
        for zero in ["0", "-0", "0s", "-0s"] {
            assert_eq!(
                parse_signed_duration(zero),
                Some(SignedDuration::NonNegative(Duration::ZERO)),
                "{zero}"
            );
        }
        for invalid in ["", "-", "10", "--5s", "5 s"] {
            assert_eq!(parse_signed_duration(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn http_tokens_exclude_separators_and_whitespace() {
        assert!(is_http_token("HEAD"));
        assert!(is_http_token("get"));
        assert!(!is_http_token("GE T"));
        assert!(!is_http_token("GET\r\nX: y"));
        assert!(!is_http_token(""));
    }
}
