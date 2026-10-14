use super::*;
use crate::TproxySettings;
impl Parser<'_> {
    pub(super) fn parse_tproxy(&mut self, inbound: &Value, index: usize) -> Option<TproxySettings> {
        let path = format!("$.inbounds[{index}]");
        let settings = inbound.get("settings").filter(|s| s.is_object());
        let Some(settings) = settings else {
            self.error(
                format!("{path}.settings"),
                "TPROXY requires dokodemo-door settings",
            );
            return None;
        };
        self.reject_unknown_fields(
            settings,
            &format!("{path}.settings"),
            &surface::TPROXY_SETTINGS,
        );
        if settings.get("followRedirect").and_then(Value::as_bool) != Some(true) {
            self.error(
                format!("{path}.settings.followRedirect"),
                "only transparent dokodemo-door with followRedirect=true is supported",
            );
        }
        let network = settings
            .get("network")
            .filter(|v| !v.is_null())
            .or_else(|| settings.get("allowedNetwork"));
        let mut tcp = false;
        let mut udp = false;
        let values = match network {
            None | Some(Value::Null) => vec!["tcp"],
            Some(Value::String(s)) => s.split(',').collect(),
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| {
                    if v.as_str().is_none() {
                        self.error(
                            format!("{path}.settings.network"),
                            "network entries must be strings",
                        );
                    }
                    v.as_str()
                })
                .collect(),
            _ => {
                self.error(
                    format!("{path}.settings.network"),
                    "network must be tcp, udp or tcp,udp",
                );
                vec![]
            }
        };
        for value in values {
            match value.to_ascii_lowercase().as_str() {
                "tcp" => tcp = true,
                "udp" => udp = true,
                _ => self.error(
                    format!("{path}.settings.network"),
                    "only tcp and udp are supported",
                ),
            };
        }
        if !tcp && !udp {
            self.error(
                format!("{path}.settings.network"),
                "at least one network is required",
            );
        }
        let stream = inbound.get("streamSettings").filter(|s| s.is_object());
        let Some(stream) = stream else {
            self.error(
                format!("{path}.streamSettings"),
                "TPROXY requires streamSettings.sockopt.tproxy=tproxy",
            );
            return None;
        };
        self.reject_unknown_fields(
            stream,
            &format!("{path}.streamSettings"),
            &surface::TPROXY_STREAM,
        );
        if stream
            .get("network")
            .is_some_and(|n| !n.is_null() && !matches!(n.as_str(), Some("tcp" | "raw")))
            || stream
                .get("security")
                .is_some_and(|n| !n.is_null() && !matches!(n.as_str(), Some("" | "none")))
        {
            self.error(
                format!("{path}.streamSettings"),
                "TPROXY supports raw transport without transport security",
            );
        }
        let sockopt = stream.get("sockopt").filter(|s| s.is_object());
        let Some(sockopt) = sockopt else {
            self.error(
                format!("{path}.streamSettings.sockopt"),
                "TPROXY requires sockopt.tproxy=tproxy",
            );
            return None;
        };
        self.reject_unknown_fields(
            sockopt,
            &format!("{path}.streamSettings.sockopt"),
            &surface::TPROXY_SOCKOPT,
        );
        if sockopt.get("tproxy").and_then(Value::as_str) != Some("tproxy") {
            self.error(
                format!("{path}.streamSettings.sockopt.tproxy"),
                "only Linux tproxy mode is supported; redirect is unsupported",
            );
        }
        let mark = self
            .optional_u32_at(
                sockopt,
                "mark",
                format!("{path}.streamSettings.sockopt.mark"),
            )
            .unwrap_or(0);
        if inbound
            .get("listen")
            .is_some_and(|v| v.as_str().is_none_or(|s| s.parse::<IpAddr>().is_err()))
        {
            self.error(
                format!("{path}.listen"),
                "TPROXY listen must be an IPv4 or IPv6 literal",
            );
        }
        if mark > i32::MAX as u32 {
            self.error(
                format!("{path}.streamSettings.sockopt.mark"),
                "mark must be a nonnegative i32",
            );
        }
        Some(TproxySettings { tcp, udp, mark })
    }
}
