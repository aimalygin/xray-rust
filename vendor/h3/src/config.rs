use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

/// Configures the HTTP/3 connection
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The MAX_FIELD_SECTION_SIZE in HTTP/3 refers to the maximum size of the dynamic table used in HPACK compression.
    /// HPACK is the compression algorithm used in HTTP/3 to reduce the size of the header fields in HTTP requests and responses.

    /// In HTTP/3, the MAX_FIELD_SECTION_SIZE is set to 12.
    /// This means that the dynamic table used for HPACK compression can have a maximum size of 2^12 bytes, which is 4KB.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,
    /// xray-rust: the draft-00 HTTP Datagram setting (0x276) set to 1
    pub(crate) enable_datagram_draft00: bool,
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        let defaults: Self = Default::default();
        Self {
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(defaults.max_field_section_size),
            enable_webtransport: settings
                .get(frame::SettingId::ENABLE_WEBTRANSPORT)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_webtransport),
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .unwrap_or(defaults.max_webtransport_sessions),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_extended_connect),
            // quic-go's MASQUE clients take only the value 1.
            enable_datagram_draft00: settings.get(frame::SettingId::H3_DATAGRAM_DRAFT00) == Some(1),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let Config {
            send_grease,
            #[cfg(test)]
                send_settings: _,
            settings:
                Settings {
                    max_field_section_size,
                    enable_webtransport,
                    enable_extended_connect,
                    enable_datagram,
                    max_webtransport_sessions,
                    enable_datagram_draft00,
                },
        } = value;

        if send_grease {
            //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
            //# integer values of N are reserved to exercise the requirement that
            //# unknown identifiers be ignored.  Such settings have no defined
            //# meaning.  Endpoints SHOULD include at least one such setting in their
            //# SETTINGS frame.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers that were defined in [HTTP/2] where there is no
            //# corresponding HTTP/3 setting have also been reserved
            //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
            //# their receipt MUST be treated as a connection error of type
            //# H3_SETTINGS_ERROR.
            match settings.insert(frame::SettingId::grease(), 0) {
                Ok(_) => (),
                Err(_err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
                }
            }
        }

        settings.insert(
            frame::SettingId::MAX_HEADER_LIST_SIZE,
            max_field_section_size,
        )?;
        // xray-rust: an extension setting whose value is its default (0) is
        // left out, as quic-go's http3 does, instead of being sent as 0.
        for (id, value) in [
            (
                frame::SettingId::ENABLE_CONNECT_PROTOCOL,
                enable_extended_connect as u64,
            ),
            (
                frame::SettingId::ENABLE_WEBTRANSPORT,
                enable_webtransport as u64,
            ),
            (frame::SettingId::H3_DATAGRAM, enable_datagram as u64),
            (
                frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
                max_webtransport_sessions,
            ),
            (
                frame::SettingId::H3_DATAGRAM_DRAFT00,
                enable_datagram_draft00 as u64,
            ),
        ] {
            if value != 0 {
                settings.insert(id, value)?;
            }
        }

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_extended_connect: false,
            enable_datagram: false,
            max_webtransport_sessions: 0,
            enable_datagram_draft00: false,
        }
    }
}

impl Settings {
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }

    /// xray-rust: whether the draft-00 HTTP Datagram setting (0x276) is 1
    pub fn enable_datagram_draft00(&self) -> bool {
        self.enable_datagram_draft00
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            #[cfg(test)]
            send_settings: true,
            settings: Default::default(),
        }
    }
}

#[cfg(test)]
mod xray_tests {
    use super::*;

    /// quic-go's http3 client sends MAX_FIELD_SECTION_SIZE and nothing else
    /// when datagrams and extended CONNECT are off.
    #[test]
    fn default_extension_settings_are_left_out() {
        let mut config = Config::default();
        config.send_grease = false;
        config.settings.max_field_section_size = 10 << 20;
        let settings = frame::Settings::try_from(config).unwrap();
        let mut encoded = Vec::new();
        settings.encode(&mut encoded);
        // SETTINGS (0x4), length 5, id 0x6, varint 10 MiB.
        assert_eq!(encoded, [0x04, 0x05, 0x06, 0x80, 0xa0, 0x00, 0x00]);
    }

    /// Xray's WARP dial announces 0x276 = 1 after quic-go's two settings,
    /// and its check of the server takes only the value 1.
    #[test]
    fn draft_datagram_setting_goes_last_and_reads_back_only_as_one() {
        let mut config = Config::default();
        config.send_grease = false;
        config.settings.max_field_section_size = 10 << 20;
        config.settings.enable_datagram = true;
        config.settings.enable_datagram_draft00 = true;
        let settings = frame::Settings::try_from(config).unwrap();
        let mut encoded = Vec::new();
        settings.encode(&mut encoded);
        assert_eq!(
            encoded,
            [0x04, 0x0a, 0x06, 0x80, 0xa0, 0x00, 0x00, 0x33, 0x01, 0x42, 0x76, 0x01]
        );
        assert!(Settings::from(&settings).enable_datagram_draft00());
        let mut other = frame::Settings::default();
        other
            .insert(frame::SettingId::H3_DATAGRAM_DRAFT00, 2)
            .unwrap();
        assert!(!Settings::from(&other).enable_datagram_draft00());
        assert!(!Settings::from(&frame::Settings::default()).enable_datagram_draft00());
    }

    #[test]
    fn enabled_extension_settings_are_still_sent() {
        let mut config = Config::default();
        config.send_grease = false;
        config.settings.enable_datagram = true;
        config.settings.enable_extended_connect = true;
        let settings = frame::Settings::try_from(config).unwrap();
        assert_eq!(settings.get(frame::SettingId::H3_DATAGRAM), Some(1));
        assert_eq!(
            settings.get(frame::SettingId::ENABLE_CONNECT_PROTOCOL),
            Some(1)
        );
        assert_eq!(settings.get(frame::SettingId::ENABLE_WEBTRANSPORT), None);
    }
}
