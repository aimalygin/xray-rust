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
/// The set is deliberately not a superset. Xray-core v26.7.28 added explicit
/// names for the current auto profiles -- `hellochrome_133`,
/// `hellofirefox_148`, and `hellosafari_26_3` -- so those aliases are included
/// here. Other uTLS-only names remain rejected: accepting one would let a
/// profile parse here and fail on xray-core with `unknown "fingerprint"`.
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

/// Xray's `ModernFingerprints` (`transport/internet/tls/tls.go`), in Xray's
/// own source order.
///
/// This is the set `fingerprint: "random"` draws from. Xray's `init()` picks
/// one member with `crypto/rand` at process start and pins it for the
/// process's lifetime, so the name resolves to a different real browser on
/// every install.
///
/// Plain TLS keeps this complete upstream pool. REALITY uses the smaller
/// [`XRAY_REALITY_MODERN_FINGERPRINTS`] pool because the new server rejects
/// older key shares that are still valid for ordinary TLS.
pub const XRAY_MODERN_FINGERPRINTS: &[&str] = &[
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
];

/// Safe per-process choices for REALITY v26.10.21. The server requires a
/// final X25519MLKEM768 share before any optional ordinary X25519 share.
pub const XRAY_REALITY_MODERN_FINGERPRINTS: &[&str] = &[
    "hellofirefox_148",
    "hellochrome_131",
    "hellochrome_133",
    "hellosafari_26_3",
];

/// The TLS 1.2-era profiles, under every alias: their ClientHello carries no
/// X25519 key share, so REALITY has nothing to derive its authentication
/// from. Xray-core's client fails them at dial time; they are rejected here
/// before dialing.
pub const XRAY_REALITY_INCAPABLE_FINGERPRINTS: &[&str] = &[
    "android",
    "360",
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

/// Every name REALITY can authenticate with, which is every name Xray-core's
/// client accepts outside [`XRAY_REALITY_INCAPABLE_FINGERPRINTS`]. Whether
/// the server accepts the hello depends on its version; see
/// [`XRAY_REALITY_HYBRID_FINGERPRINTS`].
pub const XRAY_REALITY_CAPABLE_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "edge",
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

/// The REALITY-capable names whose ClientHello carries an X25519MLKEM768 key
/// share before any ordinary X25519 one. REALITY servers from Xray-core
/// v26.10.21 on refuse every other hello; older servers accept any
/// REALITY-capable name, which is why the rest stay selectable. `random` and
/// `randomized` belong here because REALITY draws them from
/// [`XRAY_REALITY_MODERN_FINGERPRINTS`], and `randomizednoalpn` and
/// `hellorandomized` because their frozen snapshots lead with the hybrid share.
pub const XRAY_REALITY_HYBRID_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "random",
    "randomized",
    "randomizednoalpn",
    "hellofirefox_148",
    "hellochrome_131",
    "hellochrome_133",
    "hellosafari_26_3",
    "hellorandomized",
    "hellofirefox_auto",
    "hellochrome_auto",
    "hellosafari_auto",
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

/// Whether REALITY servers from Xray-core v26.10.21 on accept the name's
/// ClientHello. A supported name outside this set still works against older
/// servers, so callers warn instead of rejecting it.
pub fn is_reality_fingerprint_hybrid(name: &str) -> bool {
    normalize_utls_fingerprint(name)
        .is_some_and(|fingerprint| XRAY_REALITY_HYBRID_FINGERPRINTS.contains(&fingerprint))
}

#[cfg(test)]
mod tests {
    use super::{
        is_reality_fingerprint_hybrid, is_reality_fingerprint_supported,
        normalize_reality_supported_fingerprint, normalize_tls_fingerprint,
        normalize_utls_fingerprint, DEFAULT_UTLS_FINGERPRINT, UNSAFE_TLS_FINGERPRINT,
        XRAY_MODERN_FINGERPRINTS, XRAY_REALITY_CAPABLE_FINGERPRINTS,
        XRAY_REALITY_HYBRID_FINGERPRINTS, XRAY_REALITY_INCAPABLE_FINGERPRINTS,
        XRAY_REALITY_MODERN_FINGERPRINTS, XRAY_UTLS_FINGERPRINTS,
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

    /// Xray-core v26.7.28 promotes the current auto browser shapes into its
    /// explicit fingerprint namespace. Each must parse for both plain TLS and
    /// REALITY, while retaining the accepted preset and `_auto` aliases.
    #[test]
    fn accepts_xray_v26_7_28_explicit_auto_profile_names() {
        for fingerprint in ["hellochrome_133", "hellofirefox_148", "hellosafari_26_3"] {
            assert_eq!(
                normalize_utls_fingerprint(fingerprint),
                Some(fingerprint),
                "{fingerprint} must be part of Xray's fingerprint namespace"
            );
            assert_eq!(
                normalize_tls_fingerprint(fingerprint),
                Some(fingerprint),
                "{fingerprint}"
            );
            assert_eq!(
                normalize_reality_supported_fingerprint(fingerprint),
                Some(fingerprint),
                "{fingerprint}"
            );
        }
    }

    /// Every explicit v26.7.28 name keeps the preset and `_auto` aliases that
    /// emit the same bytes -- `Chrome-133`, `Firefox-148`, `Safari-26.3` in
    /// `docs/shaped-rustls-utls-fingerprint-parity-report.md`.
    #[test]
    fn current_auto_profile_shapes_keep_all_xray_aliases() {
        for fingerprint in [
            "chrome",
            "hellochrome_auto",
            "hellochrome_133",
            "firefox",
            "hellofirefox_auto",
            "hellofirefox_148",
            "safari",
            "hellosafari_auto",
            "hellosafari_26_3",
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
            assert!(is_reality_fingerprint_hybrid(fingerprint), "{fingerprint}");
        }
    }

    /// Xray's three maps hold 63 entries. `unsafe` is a nil entry the config
    /// builder special-cases rather than a shape, and `hellogolang` names no
    /// shape at all, which leaves 61. Dropping `hellogolang` is the one place
    /// this table is narrower than Xray's -- a known divergence, recorded on
    /// [`XRAY_UTLS_FINGERPRINTS`]; if it is ever closed, this count moves.
    #[test]
    fn fingerprint_table_matches_xrays_map_union() {
        assert_eq!(XRAY_UTLS_FINGERPRINTS.len(), 61);
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
            "hellochrome_133",
            "hellochrome_131",
            "hellosafari_26_3",
        ] {
            assert_eq!(
                normalize_reality_supported_fingerprint(fingerprint),
                Some(fingerprint)
            );
            assert!(
                is_reality_fingerprint_supported(fingerprint),
                "{fingerprint}"
            );
            assert!(is_reality_fingerprint_hybrid(fingerprint), "{fingerprint}");
        }
    }

    /// Xray-core's client still dials these and servers older than v26.10.21
    /// accept them, so REALITY keeps them; only the hybrid set excludes them.
    #[test]
    fn reality_support_keeps_x25519_only_fingerprints_outside_the_hybrid_set() {
        for fingerprint in [
            "ios",
            "edge",
            "qq",
            "hellochrome_100",
            "hellochrome_120_pq",
            "hellofirefox_99",
        ] {
            assert_eq!(
                normalize_reality_supported_fingerprint(fingerprint),
                Some(fingerprint)
            );
            assert!(!is_reality_fingerprint_hybrid(fingerprint), "{fingerprint}");
        }
    }

    /// Xray's `randomizednoalpn` preset forces TLS 1.3 with an X25519 first key
    /// share, and its snapshot leads with X25519MLKEM768. The bare uTLS
    /// `hellorandomizednoalpn` keeps the default weights and its TLS 1.2
    /// snapshot.
    #[test]
    fn randomizednoalpn_preset_is_reality_capable_unlike_the_bare_utls_id() {
        assert_eq!(
            normalize_reality_supported_fingerprint("randomizednoalpn"),
            Some("randomizednoalpn")
        );
        assert!(is_reality_fingerprint_hybrid("randomizednoalpn"));
        assert!(!is_reality_fingerprint_supported("hellorandomizednoalpn"));
    }

    #[test]
    fn reality_capability_lists_partition_known_fingerprints() {
        assert_eq!(
            XRAY_REALITY_CAPABLE_FINGERPRINTS.len() + XRAY_REALITY_INCAPABLE_FINGERPRINTS.len(),
            XRAY_UTLS_FINGERPRINTS.len()
        );
    }

    #[test]
    fn reality_hybrid_fingerprints_are_reality_capable() {
        for fingerprint in XRAY_REALITY_HYBRID_FINGERPRINTS {
            assert!(
                XRAY_REALITY_CAPABLE_FINGERPRINTS.contains(fingerprint),
                "{fingerprint}"
            );
        }
        // The lookup shares the name table, so case and the empty default
        // behave as they do everywhere else.
        assert!(is_reality_fingerprint_hybrid("Chrome"));
        assert!(is_reality_fingerprint_hybrid(""));
        assert!(!is_reality_fingerprint_hybrid("madeup-browser"));
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

    /// REALITY draws only from the part of Xray's pool that v26.10.21 servers
    /// accept. The rest of the pool stays selectable by name.
    #[test]
    fn reality_random_pool_is_the_hybrid_part_of_xrays_pool() {
        let hybrid_part = XRAY_MODERN_FINGERPRINTS
            .iter()
            .copied()
            .filter(|fingerprint| is_reality_fingerprint_hybrid(fingerprint))
            .collect::<Vec<_>>();
        assert_eq!(hybrid_part, XRAY_REALITY_MODERN_FINGERPRINTS);
        for fingerprint in XRAY_MODERN_FINGERPRINTS {
            assert!(
                is_reality_fingerprint_supported(fingerprint),
                "{fingerprint}"
            );
        }
    }

    /// A drawn name is resolved through the ordinary fingerprint table, which
    /// has no entry for the drawing names themselves. One of them appearing
    /// here would resolve to nothing and fail every dial that drew it --
    /// intermittently, on one install in eleven.
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
        assert_eq!(XRAY_MODERN_FINGERPRINTS.len(), 11);
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
