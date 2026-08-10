pub const DEFAULT_UTLS_FINGERPRINT: &str = "chrome";

/// Every `fingerprint` name Xray's config builder accepts.
///
/// This is the union of the three maps `GetFingerprint`
/// (`transport/internet/tls/tls.go`) consults in order -- `PresetFingerprints`,
/// `ModernFingerprints`, `OtherFingerprints` -- minus two names that are not
/// plain table lookups there: `unsafe`, whose map entry stays nil and which
/// [`normalize_tls_fingerprint`] special-cases, and `hellogolang`.
///
/// Excluding `hellogolang` is a known divergence, and the one direction in
/// which this set is narrower than Xray's: the name parses on xray-core for
/// plain TLS (`infra/conf/transport_internet.go:700`) and is rejected here. In
/// uTLS it does not name a shape at all -- it means emit Go's own `crypto/tls`
/// ClientHello and apply no shaping, which is what `unsafe` already does
/// through a different TLS stack. REALITY rejects it and `unsafe` on one line
/// (`infra/conf/transport_internet.go:925`), so that path is unaffected. See
/// `docs/superpowers/plans/2026-08-07-hellogolang-divergence.md`.
///
/// The set is deliberately not a superset. uTLS knows `ClientHelloID`s Xray
/// has never mapped -- `hellochrome_133`, `hellofirefox_148`, `hellosafari_26_3`
/// among them -- and accepting one would let a profile parse here and fail on
/// xray-core with `unknown "fingerprint"`. They also buy nothing: each is the
/// shape its `_auto` alias already resolves to, so `chrome`, `firefox` and
/// `safari` emit those exact bytes. See
/// `normalize_utls_fingerprint_rejects_names_xray_never_mapped`.
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
    "hellochrome_120",
    "hellochrome_131",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
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

/// Xray's `ModernFingerprints` (`transport/internet/tls/tls.go`), in Xray's
/// own source order.
///
/// This is the set `fingerprint: "random"` draws from. Xray's `init()` picks
/// one member with `crypto/rand` at process start and pins it for the
/// process's lifetime, so the name resolves to a different real browser on
/// every install.
///
/// Two properties this list has to keep, both asserted below: every member is
/// a name [`normalize_utls_fingerprint`] already knows, and every member is
/// REALITY-capable. The second is what lets `random` stay in
/// [`XRAY_REALITY_CAPABLE_FINGERPRINTS`] -- whatever it draws must itself be
/// usable for a REALITY handshake.
pub const XRAY_MODERN_FINGERPRINTS: &[&str] = &[
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellofirefox_120",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "hellochrome_120",
    "hellochrome_131",
    "helloios_13",
    "helloios_14",
    "helloedge_85",
    "helloedge_106",
    "hellosafari_16_0",
    "hello360_11_0",
    "helloqq_11_1",
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
    "hellochrome_120",
    "hellochrome_131",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
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
        UNSAFE_TLS_FINGERPRINT, XRAY_MODERN_FINGERPRINTS, XRAY_REALITY_CAPABLE_FINGERPRINTS,
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

    /// uTLS exposes `ClientHelloID`s that Xray's config builder has never put
    /// in a map, so a name can be perfectly real and still be rejected by
    /// xray-core. Checked against Xray-core v26.5.9: none of these appear in
    /// `PresetFingerprints`, `ModernFingerprints` or `OtherFingerprints`, the
    /// three maps `GetFingerprint` consults, so `infra/conf` answers each with
    /// `unknown "fingerprint"`.
    ///
    /// Accepting one would be a superset divergence -- the profile parses here
    /// and breaks the moment it is moved to xray-core -- and it would buy no
    /// shape we cannot already reach: each of these is what an accepted `_auto`
    /// name resolves to, asserted below.
    #[test]
    fn normalize_utls_fingerprint_rejects_names_xray_never_mapped() {
        for fingerprint in ["hellochrome_133", "hellofirefox_148", "hellosafari_26_3"] {
            assert_eq!(
                normalize_utls_fingerprint(fingerprint),
                None,
                "{fingerprint} is a real uTLS name but not an Xray one"
            );
            assert_eq!(
                normalize_tls_fingerprint(fingerprint),
                None,
                "{fingerprint}"
            );
            assert_eq!(
                normalize_reality_supported_fingerprint(fingerprint),
                None,
                "{fingerprint}"
            );
        }
    }

    /// The names that replace the three above. Each is accepted by Xray and by
    /// us, and each emits the same bytes the dropped name did -- `Chrome-133`,
    /// `Firefox-148`, `Safari-26.3` in
    /// `docs/shaped-rustls-utls-fingerprint-parity-report.md`.
    #[test]
    fn every_shape_behind_a_dropped_name_stays_reachable() {
        for fingerprint in [
            "chrome",
            "hellochrome_auto",
            "firefox",
            "hellofirefox_auto",
            "safari",
            "hellosafari_auto",
        ] {
            assert_eq!(
                normalize_utls_fingerprint(fingerprint),
                Some(fingerprint),
                "{fingerprint}"
            );
            assert!(
                is_reality_fingerprint_supported(fingerprint),
                "{fingerprint}"
            );
        }
    }

    /// Xray's three maps hold 60 entries. `unsafe` is a nil entry the config
    /// builder special-cases rather than a shape, and `hellogolang` names no
    /// shape at all, which leaves 58. Dropping `hellogolang` is the one place
    /// this table is narrower than Xray's -- a known divergence, recorded on
    /// [`XRAY_UTLS_FINGERPRINTS`]; if it is ever closed, this count moves.
    #[test]
    fn fingerprint_table_matches_xrays_map_union() {
        assert_eq!(XRAY_UTLS_FINGERPRINTS.len(), 58);
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

    /// The draw feeds its result straight back into the name lookup, so a
    /// member Xray knows but we do not would resolve to nothing.
    #[test]
    fn modern_fingerprints_are_all_known_names() {
        for fingerprint in XRAY_MODERN_FINGERPRINTS {
            assert_eq!(
                normalize_utls_fingerprint(fingerprint),
                Some(*fingerprint),
                "{fingerprint}"
            );
        }
    }

    /// `random` is REALITY-capable, so everything it can draw has to be too.
    /// Xray gets this for free because `ModernFingerprints` happens to hold
    /// only X25519-bearing profiles; nothing enforces it there, so we assert
    /// it here.
    #[test]
    fn modern_fingerprints_are_all_reality_capable() {
        for fingerprint in XRAY_MODERN_FINGERPRINTS {
            assert!(
                is_reality_fingerprint_supported(fingerprint),
                "{fingerprint} is drawable by `random`, which REALITY accepts"
            );
        }
    }

    /// A drawn name is resolved through the ordinary fingerprint table, which
    /// has no entry for the drawing names themselves. One of them appearing
    /// here would resolve to nothing and fail every dial that drew it --
    /// intermittently, on one install in nineteen.
    #[test]
    fn modern_fingerprints_contain_no_drawing_names() {
        for fingerprint in XRAY_MODERN_FINGERPRINTS {
            assert!(
                !matches!(*fingerprint, "random" | "randomized" | "randomizednoalpn"),
                "{fingerprint}"
            );
        }
    }

    #[test]
    fn modern_fingerprints_match_xrays_table_size() {
        assert_eq!(XRAY_MODERN_FINGERPRINTS.len(), 19);
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
