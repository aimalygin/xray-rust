pub const DEFAULT_UTLS_FINGERPRINT: &str = "chrome";

pub const XRAY_UTLS_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "randomizednoalpn",
    "hellofirefox_120",
    "hellofirefox_148",
    "hellochrome_120",
    "hellochrome_131",
    "hellochrome_133",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
    "hellosafari_26_3",
    "hello360_11_0",
    "helloqq_11_1",
    "hellorandomized",
    "hellorandomizedalpn",
    "hellorandomizednoalpn",
    "hellofirefox_auto",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellofirefox_63",
    "hellofirefox_65",
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellochrome_auto",
    "hellochrome_58",
    "hellochrome_62",
    "hellochrome_70",
    "hellochrome_72",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "helloios_auto",
    "helloios_11_1",
    "helloios_12_1",
    "helloandroid_11_okhttp",
    "helloedge_85",
    "helloedge_auto",
    "hellosafari_16_0",
    "hellosafari_auto",
    "hello360_auto",
    "hello360_7_5",
    "helloqq_auto",
    "hellochrome_100_psk",
    "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf",
    "hellochrome_115_pq",
    "hellochrome_115_pq_psk",
    "hellochrome_120_pq",
];

pub const XRAY_REALITY_INCAPABLE_FINGERPRINTS: &[&str] = &[
    "android",
    "360",
    "randomizednoalpn",
    "hellorandomizedalpn",
    "hellorandomizednoalpn",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellochrome_58",
    "hellochrome_62",
    "helloios_11_1",
    "helloios_12_1",
    "helloandroid_11_okhttp",
    "hello360_auto",
    "hello360_7_5",
];

pub const XRAY_REALITY_CAPABLE_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "edge",
    "qq",
    "random",
    "randomized",
    "hellofirefox_120",
    "hellofirefox_148",
    "hellochrome_120",
    "hellochrome_131",
    "hellochrome_133",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
    "hellosafari_26_3",
    "hello360_11_0",
    "helloqq_11_1",
    "hellorandomized",
    "hellofirefox_auto",
    "hellofirefox_63",
    "hellofirefox_65",
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellochrome_auto",
    "hellochrome_70",
    "hellochrome_72",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "helloios_auto",
    "helloedge_85",
    "helloedge_auto",
    "hellosafari_16_0",
    "hellosafari_auto",
    "helloqq_auto",
    "hellochrome_100_psk",
    "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf",
    "hellochrome_115_pq",
    "hellochrome_115_pq_psk",
    "hellochrome_120_pq",
];

/// Looks a name up in Xray's uTLS fingerprint table, defaulting an empty name
/// to `chrome`.
///
/// This is the shared lookup both `security` modes build on, so it knows
/// nothing about either one's extra rules. Callers almost always want a
/// mode-specific wrapper instead: [`normalize_tls_fingerprint`] for
/// `tlsSettings`, which additionally honours the `unsafe` sentinel, or
/// [`normalize_reality_supported_fingerprint`] for `realitySettings`, which
/// additionally rejects names without an X25519 key share.
pub fn normalize_utls_fingerprint(name: &str) -> Option<&'static str> {
    let name = if name.is_empty() {
        DEFAULT_UTLS_FINGERPRINT
    } else {
        name
    };

    XRAY_UTLS_FINGERPRINTS
        .iter()
        .copied()
        .find(|fingerprint| fingerprint.eq_ignore_ascii_case(name))
}

/// Xray's escape hatch: `fingerprint: "unsafe"` disables uTLS shaping and lets
/// the TLS stack send its own ClientHello. Its entry in Xray's fingerprint map
/// is permanently nil, unlike `random`/`randomized`, which `init()` fills with
/// real profiles at startup.
pub const UNSAFE_TLS_FINGERPRINT: &str = "unsafe";

/// Normalizes a `tlsSettings.fingerprint` value.
///
/// Reads the same [`XRAY_UTLS_FINGERPRINTS`] table REALITY does — Xray shares
/// one uTLS fingerprint namespace across both — but without the X25519
/// key-share requirement, which is a REALITY protocol constraint rather than a
/// property of the fingerprint. An empty name means `chrome`, matching Xray's
/// `GetFingerprint("")`.
pub fn normalize_tls_fingerprint(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case(UNSAFE_TLS_FINGERPRINT) {
        return Some(UNSAFE_TLS_FINGERPRINT);
    }

    normalize_utls_fingerprint(name)
}

pub fn normalize_reality_supported_fingerprint(name: &str) -> Option<&'static str> {
    let fingerprint = normalize_utls_fingerprint(name)?;
    XRAY_REALITY_CAPABLE_FINGERPRINTS
        .iter()
        .copied()
        .find(|candidate| *candidate == fingerprint)
}

pub fn is_reality_fingerprint_supported(name: &str) -> bool {
    normalize_reality_supported_fingerprint(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        is_reality_fingerprint_supported, normalize_reality_supported_fingerprint,
        normalize_tls_fingerprint, normalize_utls_fingerprint, DEFAULT_UTLS_FINGERPRINT,
        UNSAFE_TLS_FINGERPRINT, XRAY_REALITY_CAPABLE_FINGERPRINTS,
        XRAY_REALITY_INCAPABLE_FINGERPRINTS, XRAY_UTLS_FINGERPRINTS,
    };

    #[test]
    fn normalize_utls_fingerprint_defaults_empty_to_chrome() {
        assert_eq!(
            normalize_utls_fingerprint(""),
            Some(DEFAULT_UTLS_FINGERPRINT)
        );
    }

    #[test]
    fn normalize_utls_fingerprint_accepts_case_insensitive_names() {
        assert_eq!(normalize_utls_fingerprint("FireFox"), Some("firefox"));
    }

    #[test]
    fn normalize_utls_fingerprint_accepts_every_xray_name() {
        for fingerprint in XRAY_UTLS_FINGERPRINTS {
            assert_eq!(
                normalize_utls_fingerprint(fingerprint),
                Some(*fingerprint),
                "{fingerprint}"
            );
        }
    }

    #[test]
    fn normalize_utls_fingerprint_rejects_names_outside_the_table() {
        for fingerprint in ["unsafe", "hellogolang", "madeup-browser"] {
            assert_eq!(
                normalize_utls_fingerprint(fingerprint),
                None,
                "{fingerprint}"
            );
        }
    }

    #[test]
    fn reality_support_rejects_known_fingerprints_without_key_share() {
        for fingerprint in XRAY_REALITY_INCAPABLE_FINGERPRINTS {
            assert!(
                normalize_utls_fingerprint(fingerprint).is_some(),
                "{fingerprint}"
            );
            assert!(
                !is_reality_fingerprint_supported(fingerprint),
                "{fingerprint}"
            );
            assert_eq!(normalize_reality_supported_fingerprint(fingerprint), None);
        }
    }

    #[test]
    fn reality_support_accepts_modern_key_share_fingerprints() {
        for fingerprint in [
            "chrome",
            "firefox",
            "hellochrome_100",
            "hellochrome_131",
            "hellochrome_115_pq",
        ] {
            assert_eq!(
                normalize_reality_supported_fingerprint(fingerprint),
                Some(fingerprint)
            );
            assert!(
                is_reality_fingerprint_supported(fingerprint),
                "{fingerprint}"
            );
        }
    }

    #[test]
    fn reality_capability_lists_partition_known_fingerprints() {
        assert_eq!(
            XRAY_REALITY_CAPABLE_FINGERPRINTS.len() + XRAY_REALITY_INCAPABLE_FINGERPRINTS.len(),
            XRAY_UTLS_FINGERPRINTS.len()
        );
    }

    #[test]
    fn normalize_tls_fingerprint_defaults_empty_to_chrome() {
        assert_eq!(
            normalize_tls_fingerprint(""),
            Some(DEFAULT_UTLS_FINGERPRINT)
        );
    }

    #[test]
    fn normalize_tls_fingerprint_passes_through_the_unsafe_sentinel() {
        assert_eq!(
            normalize_tls_fingerprint("unsafe"),
            Some(UNSAFE_TLS_FINGERPRINT)
        );
        assert_eq!(
            normalize_tls_fingerprint("UNSAFE"),
            Some(UNSAFE_TLS_FINGERPRINT)
        );
    }

    #[test]
    fn normalize_tls_fingerprint_accepts_reality_incapable_names() {
        // Plain TLS has no X25519 key-share requirement, so every name in the
        // table is usable even when REALITY rejects it.
        for name in XRAY_REALITY_INCAPABLE_FINGERPRINTS {
            assert_eq!(
                normalize_tls_fingerprint(name),
                Some(*name),
                "plain TLS must accept {name}"
            );
            assert_eq!(
                normalize_reality_supported_fingerprint(name),
                None,
                "{name} is expected to stay REALITY-incapable"
            );
        }
    }

    #[test]
    fn normalize_tls_fingerprint_rejects_unknown_names() {
        assert_eq!(normalize_tls_fingerprint("nosuchbrowser"), None);
    }
}
