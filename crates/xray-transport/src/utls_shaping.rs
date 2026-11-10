//! Translates a uTLS ClientHello profile into a rustls `ClientHelloPlan`.
//!
//! `apply_utls_profile` sets everything the profile describes — cipher
//! suites, extensions, GREASE, padding — but deliberately leaves the hello
//! random, session id, and key share untouched; filling those in is the
//! caller's responsibility. That split is what lets REALITY's customizer
//! (which pins all three for its handshake patching) and the plain-TLS
//! customizer (which leaves them to rustls, bar the session id a TLS-1.2-era
//! profile needs put back) share this same plan-building logic.
//!
//! Callers that need to override part of the shaped plan may do so after
//! `apply_utls_profile` returns: `ClientHelloPlan` setters are last-write-wins
//! and the plan is only read once, at encode time. Replacing a list is not
//! always enough to change the hello, though — an extension the profile never
//! declared is suppressed no matter what payload it is given — and the ALPN
//! list also moves the padding, so an ALPN override is an argument of
//! `apply_utls_profile` rather than a bare `.with_alpn_protocols(...)`.

use rand::{rngs::OsRng, RngCore};
use rustls::{
    client::{
        ClientHelloAdvertisedSupportedGroups, ClientHelloAdvertisedSupportedVersions,
        ClientHelloAlpnProtocols, ClientHelloCertificateCompressionAlgorithms,
        ClientHelloCipherSuites, ClientHelloContext, ClientHelloExactExtension,
        ClientHelloExactExtensions, ClientHelloExtensionOrder, ClientHelloExtensionPlan,
        ClientHelloForcedExtensions, ClientHelloGreaseExtension, ClientHelloGreasePlan,
        ClientHelloKeySharePlan, ClientHelloPaddingPlan, ClientHelloPlan, ClientHelloRawExtension,
        ClientHelloRawExtensions, ClientHelloRawKeyShare, ClientHelloRawKeyShares,
        ClientHelloSupportedGroups, ClientHelloSupportedVersions,
    },
    CertificateCompressionAlgorithm, CipherSuite, Error as RustlsError, NamedGroup,
    ProtocolVersion,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::sudoku::gorand::{crypto_rand_int63, GoRand};
use crate::utls_profiles::{UtlsClientHelloProfile, UtlsEchGrease};

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_COOKIE: u16 = 0x002c;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_CERTIFICATE_COMPRESSION: u16 = 0x001b;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_DELEGATED_CREDENTIALS: u16 = 0x0022;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// `trust_anchors`, draft-ietf-tls-trust-anchor-ids (uTLS's
/// `utlsExtensionTrustAnchors`).
const EXT_TRUST_ANCHORS: u16 = 0xca34;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_X25519_MLKEM768_DRAFT: u16 = 0x6399;
const TLS_VERSION_1_3: u16 = 0x0304;
/// Length of the `enc` field in an ECH GREASE outer hello: uTLS sets its HPKE
/// KEM to `DHKEM_X25519_HKDF_SHA256`, whose encapsulated key is an X25519
/// public key.
const ENCAPSULATED_KEY_LEN: usize = 32;
const ZLIB_CERTIFICATE_COMPRESSION: u16 = 0x0001;
const BROTLI_CERTIFICATE_COMPRESSION: u16 = 0x0002;
const ZSTD_CERTIFICATE_COMPRESSION: u16 = 0x0003;
const STRUCTURED_OPTIONAL_EXTENSIONS: &[u16] = &[
    EXT_SERVER_NAME,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_EC_POINT_FORMATS,
    EXT_ALPN,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_CERTIFICATE_COMPRESSION,
    EXT_SESSION_TICKET,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_RENEGOTIATION_INFO,
];

/// BoringSSL's GREASE slots, as uTLS numbers its per-hello seeds
/// (`ssl_grease_cipher` … `ssl_grease_signature_algorithm`).
const GREASE_SEEDS: usize = 8;
const GREASE_CIPHER: usize = 0;
const GREASE_GROUP: usize = 1;
const GREASE_EXTENSION1: usize = 2;
const GREASE_EXTENSION2: usize = 3;
const GREASE_VERSION: usize = 4;
const GREASE_SIGNATURE_ALGORITHM: usize = 7;

/// What uTLS draws anew for every hello of a profile: the GREASE value of
/// each slot, the cipher suite and payload length of a GREASE ECH extension,
/// and for a Chrome profile whose spec runs `ShuffleChromeTLSExtensions`, the
/// extension order.
///
/// One draw serves the whole hello, a HelloRetryRequest's second flight
/// included, since the plan it shapes is built once per connection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct HelloDraws {
    grease: [u16; GREASE_SEEDS],
    order: Option<Vec<u16>>,
    ech: Option<EchDraw>,
    /// Where a HelloRetryRequest's cookie goes, as a fraction of the places
    /// uTLS allows (`cookie_place`).
    cookie: u32,
}

/// The cipher suite and payload length a GREASE ECH extension takes:
/// `GREASEEncryptedClientHelloExtension.init` picks an index into each of its
/// candidate lists with `rand.Int(rand.Reader, len)` (`u_ech.go`), once per
/// extension and so once per hello, a HelloRetryRequest reusing it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct EchDraw {
    aead_id: u16,
    length: usize,
}

impl EchDraw {
    pub(crate) fn draw(grease: &UtlsEchGrease) -> Result<Self, RustlsError> {
        Ok(Self {
            aead_id: draw_candidate(grease.aead_ids, "encrypted_client_hello AEAD")?,
            length: draw_candidate(grease.lengths, "encrypted_client_hello length")?,
        })
    }

    /// What an all-zero `crypto/rand` picks: index 0 of each list.
    #[cfg(test)]
    fn first(grease: &UtlsEchGrease) -> Self {
        Self {
            aead_id: grease.aead_ids[0],
            length: grease.lengths[0],
        }
    }
}

impl HelloDraws {
    /// Fresh draws for one connection, as uTLS's `ApplyPreset` reads its
    /// GREASE seeds from `crypto/rand` and `ShuffleChromeTLSExtensions` its
    /// seed from `crypto/rand.Int`.
    pub(crate) fn draw(profile: &UtlsClientHelloProfile) -> Result<Self, RustlsError> {
        let mut seeds = [0; 2 * GREASE_SEEDS];
        fill_random(&mut seeds, "GREASE")?;
        let shuffle_seed = if profile.unshuffled_extensions.is_empty() {
            None
        } else {
            Some(loop {
                let mut bytes = [0; 8];
                fill_random(&mut bytes, "the extension order")?;
                if let Some(seed) = crypto_rand_int63(bytes) {
                    break seed;
                }
            })
        };
        let ech = profile
            .encrypted_client_hello
            .as_ref()
            .map(EchDraw::draw)
            .transpose()?;
        let mut cookie = [0; 4];
        fill_random(&mut cookie, "the cookie's place")?;
        Ok(Self {
            cookie: u32::from_le_bytes(cookie),
            ..Self::from_seeds(profile, seeds, shuffle_seed, ech)
        })
    }

    /// The draws uTLS makes from `seeds`, its sixteen bytes of GREASE seeds,
    /// `shuffle_seed`, the extension shuffle's seed, for a profile that
    /// shuffles, and `ech`, its GREASE ECH extension's picks.
    fn from_seeds(
        profile: &UtlsClientHelloProfile,
        seeds: [u8; 2 * GREASE_SEEDS],
        shuffle_seed: Option<i64>,
        ech: Option<EchDraw>,
    ) -> Self {
        let mut seed = [0u16; GREASE_SEEDS];
        for (slot, bytes) in seed.iter_mut().zip(seeds.chunks_exact(2)) {
            *slot = u16::from_le_bytes([bytes[0], bytes[1]]);
        }
        // The two GREASE extensions of one hello must differ.
        if boring_grease(seed[GREASE_EXTENSION1]) == boring_grease(seed[GREASE_EXTENSION2]) {
            seed[GREASE_EXTENSION2] ^= 0x1010;
        }
        let order = shuffle_seed
            .filter(|_| !profile.unshuffled_extensions.is_empty())
            .map(|seed| chrome_shuffled_extensions(profile, seed));
        Self {
            grease: seed.map(boring_grease),
            order,
            ech,
            cookie: 0,
        }
    }

    /// The draws of an all-zero `crypto/rand`, the one the oracle fixtures
    /// are made with: `0x0a0a` in every slot but the second GREASE
    /// extension's `0x1a1a`, the order `extensions` records, and the first
    /// ECH candidates.
    #[cfg(test)]
    pub(crate) fn zero(profile: &UtlsClientHelloProfile) -> Self {
        Self::from_seeds(
            profile,
            [0; 2 * GREASE_SEEDS],
            Some(0),
            profile.encrypted_client_hello.as_ref().map(EchDraw::first),
        )
    }

    fn grease(&self, slot: usize) -> u16 {
        self.grease[slot]
    }

    /// The place among `extensions` uTLS's `p.Intn(extensions - 2)` gives a
    /// HelloRetryRequest's cookie: evenly over all but the last two.
    fn cookie_place(&self, extensions: usize) -> usize {
        let places = extensions.saturating_sub(2) as u64;
        ((u64::from(self.cookie) * places) >> 32) as usize
    }

    /// The profile's extension types in this hello's order, GREASE
    /// extensions included.
    fn extension_types(&self, profile: &UtlsClientHelloProfile) -> Vec<u16> {
        match &self.order {
            Some(order) => order.clone(),
            None => profile
                .extensions
                .iter()
                .map(|extension| extension.extension_type)
                .collect(),
        }
    }

    /// `values` with every GREASE value replaced by `slot`'s.
    fn regrease(&self, values: &[u16], slot: usize) -> Vec<u16> {
        values
            .iter()
            .map(|value| {
                if is_grease_value(*value) {
                    self.grease(slot)
                } else {
                    *value
                }
            })
            .collect()
    }
}

/// `getBoringGREASEValue`: `0x?a?a` from the high nibble of the seed's low
/// byte.
fn boring_grease(seed: u16) -> u16 {
    let value = (seed & 0xf0) | 0x0a;
    value | (value << 8)
}

/// `ShuffleChromeTLSExtensions` on the profile's spec order with `seed`: Go's
/// `rand.New(rand.NewSource(seed)).Shuffle`, skipping every swap that would
/// move a GREASE, padding or pre_shared_key extension, and then the
/// extensions this hello does not carry (padding a long hello leaves out,
/// pre_shared_key without a ticket).
fn chrome_shuffled_extensions(profile: &UtlsClientHelloProfile, seed: i64) -> Vec<u16> {
    let mut order = chrome_shuffle(profile.unshuffled_extensions, seed);
    order.retain(|extension_type| profile_has_extension(profile, *extension_type));
    order
}

fn chrome_shuffle(spec: &[u16], seed: i64) -> Vec<u16> {
    let mut order = spec.to_vec();
    GoRand::new(seed).shuffle_by(order.len(), |i, j| {
        if !stays_in_place(order[i]) && !stays_in_place(order[j]) {
            order.swap(i, j);
        }
    });
    order
}

/// The extensions `ShuffleChromeTLSExtensions` never moves.
fn stays_in_place(extension_type: u16) -> bool {
    is_grease_value(extension_type)
        || extension_type == EXT_PADDING
        || extension_type == EXT_PRE_SHARED_KEY
}

fn fill_random(bytes: &mut [u8], what: &str) -> Result<(), RustlsError> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|error| RustlsError::General(format!("{what} needs randomness: {error}")))
}

/// The plan for one hello of `profile`, with `draws` as this connection's
/// draws and `alpn_override`, when given, as the ALPN list Xray's
/// `WebsocketHandshakeContext` forces on an already shaped hello.
pub(crate) fn apply_utls_profile(
    mut plan: ClientHelloPlan,
    profile: &'static UtlsClientHelloProfile,
    context: ClientHelloContext<'_>,
    draws: &HelloDraws,
    alpn_override: Option<&[Vec<u8>]>,
) -> Result<ClientHelloPlan, RustlsError> {
    let supported_versions = supported_versions(profile)?;
    let cipher_suites = cipher_suites(profile, context, supported_versions.as_slice())?;
    let padding_offset = boringssl_padding_offset(profile, context, supported_versions.as_slice());
    plan = plan
        .with_cipher_suites(cipher_suites)
        .with_supported_versions(supported_versions);

    if !profile.supported_versions.is_empty() {
        plan =
            plan.with_advertised_supported_versions(advertised_supported_versions(profile, draws)?);
    }
    if !profile.supported_groups.is_empty() {
        plan = plan.with_supported_groups(supported_groups(profile)?);
        plan = plan.with_advertised_supported_groups(advertised_supported_groups(profile, draws)?);
    }
    if !profile.key_shares.is_empty() {
        plan = plan.with_key_share_plan(key_share_plan(profile)?);
    }
    if let Some(raw_key_shares) = raw_key_shares(profile, draws)? {
        plan = plan.with_raw_key_shares(raw_key_shares);
    }
    if !profile.alpn_protocols.is_empty() {
        plan = plan.with_alpn_protocols(alpn_protocols(profile)?);
    }
    if profile_has_supported_certificate_compression(profile) {
        plan = plan.with_certificate_compression_algorithms(certificate_compression(profile)?);
    }

    // Xray's override appends ALPN to a profile that has none.
    let appended_alpn = alpn_override.is_some() && !profile_has_extension(profile, EXT_ALPN);
    let extensions = planned_extensions(profile, draws, appended_alpn);
    let forced_extensions = forced_extensions(profile);
    let extension_plan = extension_plan(profile, appended_alpn)?;
    let (exact_extensions, raw_extensions) = extension_payloads(profile, draws)?;

    plan = plan
        .with_forced_extensions(forced_extensions)
        .with_extensions(extension_plan)
        .with_extension_order(extension_order(profile, &extensions)?);

    if let Some(exact_extensions) = exact_extensions {
        plan = plan.with_exact_extensions(exact_extensions);
    }
    if let Some(raw_extensions) = raw_extensions {
        plan = plan.with_raw_extensions(raw_extensions);
    }
    if let Some(grease) = grease_plan(profile, context, draws, &extensions)? {
        plan = plan.with_grease(grease);
    }
    if let Some(protocols) = alpn_override {
        plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(protocols.to_vec())?);
    }
    if profile.padding_length.is_some() {
        plan = plan.with_padding(ClientHelloPaddingPlan::boringssl(padding_offset)?);
    }

    Ok(plan)
}

/// What the hello uTLS sends on this connection has that this one does not,
/// in bytes: the suites this provider cannot negotiate, which the plan leaves
/// out of the cipher list, less the `supported_versions` rustls adds to a
/// TLS-1.2-era hello (one version, `0x0303`: seven bytes).
///
/// Every other extension is as long on both hellos -- the profile records
/// them as uTLS writes them, and the server name, the ALPN list or override
/// and the ECH GREASE draw go into both alike -- so shaped-rustls, applying
/// BoringSSL's padding rule to each ClientHello as it encodes it with this
/// added, pads as uTLS's own hello is padded and to its length: the second
/// ClientHello a HelloRetryRequest asks for as much as the first.
fn boringssl_padding_offset(
    profile: &UtlsClientHelloProfile,
    context: ClientHelloContext<'_>,
    supported_versions: &[ProtocolVersion],
) -> isize {
    const TLS12_SUPPORTED_VERSIONS_LEN: isize = 4 + 1 + 2;
    let filtered = profile
        .cipher_suites
        .iter()
        .filter(|suite| {
            !is_grease_value(**suite)
                && !provider_supports_cipher_suite(**suite, context, supported_versions)
        })
        .count() as isize;
    let added = if profile_has_extension(profile, EXT_SUPPORTED_VERSIONS) {
        0
    } else {
        TLS12_SUPPORTED_VERSIONS_LEN
    };
    2 * filtered - added
}

/// This hello's extensions in uTLS's order, GREASE ones included: the drawn
/// order, the ALPN extension Xray's override appends to a profile without
/// one, and the cookie a HelloRetryRequest may bring.
///
/// No uTLS spec carries a cookie extension. When a HelloRetryRequest brings
/// one, uTLS inserts it at `p.Intn(len(Extensions) - 2)`, anywhere but the last
/// two places (`handshake_client_tls13.go`). The place is drawn with the rest
/// of this hello's draws, and shaped-rustls leaves the entry out of a
/// ClientHello that carries no cookie, so only the second one a cookie asks
/// for shows it.
fn planned_extensions(
    profile: &UtlsClientHelloProfile,
    draws: &HelloDraws,
    appended_alpn: bool,
) -> Vec<u16> {
    let mut extensions = draws.extension_types(profile);
    if appended_alpn {
        extensions.push(EXT_ALPN);
    }
    if !extensions.contains(&EXT_COOKIE) {
        let place = draws.cookie_place(extensions.len());
        extensions.insert(place, EXT_COOKIE);
    }
    extensions
}

fn cipher_suites(
    profile: &UtlsClientHelloProfile,
    context: ClientHelloContext<'_>,
    supported_versions: &[ProtocolVersion],
) -> Result<ClientHelloCipherSuites, RustlsError> {
    ClientHelloCipherSuites::try_from(
        profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease_value(*suite))
            .filter(|suite| provider_supports_cipher_suite(*suite, context, supported_versions))
            .map(CipherSuite::from)
            .collect::<Vec<_>>(),
    )
}

fn provider_supports_cipher_suite(
    suite: u16,
    context: ClientHelloContext<'_>,
    supported_versions: &[ProtocolVersion],
) -> bool {
    let suite = CipherSuite::from(suite);
    context
        .crypto_provider
        .cipher_suites
        .iter()
        .any(|candidate| {
            let version = candidate.version().version;
            candidate.suite() == suite
                && supported_versions.contains(&version)
                && context
                    .versions
                    .iter()
                    .any(|enabled| enabled.version == version)
        })
}

/// Whether a handshake wearing this profile may negotiate TLS 1.3.
///
/// uTLS decides the same thing from the same place. `SetTLSVers` takes the
/// parrot's own `TLSVersMin`/`TLSVersMax` when it declares them, otherwise
/// reads the range off its `supported_versions` extension, and — when the
/// parrot carries no such extension — defaults to TLS 1.0-1.2
/// (`utls@v1.8.3-0.20260301010127-aa6edf4b11af/u_conn.go:696-732`). Every
/// parrot in `utls_profiles` either lists 0x0304 or lists nothing at all, so
/// this one test covers both branches.
///
/// The answer has to reach the rustls *config*, not just the ClientHello plan:
/// uTLS writes the ceiling into `config.MaxVersion` (`u_conn.go:748-752`) and
/// rustls reads its own config, not the plan, when it decides whether a TLS 1.2
/// ServerHello carrying the RFC 8446 §4.1.3 downgrade sentinel is an attack.
pub(crate) fn profile_offers_tls13(profile: &UtlsClientHelloProfile) -> bool {
    profile.supported_versions.contains(&TLS_VERSION_1_3)
}

fn supported_versions(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedVersions, RustlsError> {
    let versions = if profile_offers_tls13(profile) {
        vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
    } else {
        vec![ProtocolVersion::TLSv1_2]
    };
    ClientHelloSupportedVersions::try_from(versions)
}

fn advertised_supported_versions(
    profile: &UtlsClientHelloProfile,
    draws: &HelloDraws,
) -> Result<ClientHelloAdvertisedSupportedVersions, RustlsError> {
    ClientHelloAdvertisedSupportedVersions::try_from(
        draws
            .regrease(profile.supported_versions, GREASE_VERSION)
            .into_iter()
            .map(ProtocolVersion::from)
            .collect::<Vec<_>>(),
    )
}

fn supported_groups(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedGroups, RustlsError> {
    let mut groups = Vec::new();
    for group in profile.supported_groups {
        if let Some(group) = real_supported_group(*group) {
            if !groups.contains(&group) {
                groups.push(group);
            }
        }
    }
    if groups.is_empty() {
        groups.push(NamedGroup::X25519);
    }
    ClientHelloSupportedGroups::try_from(groups)
}

fn advertised_supported_groups(
    profile: &UtlsClientHelloProfile,
    draws: &HelloDraws,
) -> Result<ClientHelloAdvertisedSupportedGroups, RustlsError> {
    ClientHelloAdvertisedSupportedGroups::try_from(
        draws
            .regrease(profile.supported_groups, GREASE_GROUP)
            .into_iter()
            .map(NamedGroup::from)
            .collect::<Vec<_>>(),
    )
}

fn key_share_plan(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloKeySharePlan, RustlsError> {
    let mut groups = Vec::new();
    for key_share in profile.key_shares {
        if let Some(group) = real_key_share_group(key_share.group) {
            groups.push(group);
        }
    }
    if groups.is_empty() {
        groups.push(NamedGroup::X25519);
    }
    ClientHelloKeySharePlan::try_from(groups)
}

/// The key shares rustls does not make: the GREASE share, one zero byte in
/// the group slot's GREASE value as uTLS writes it (the value supported_groups
/// carries), and a zero-filled share for each group rustls cannot offer.
///
/// Each goes in at its place in the profile's list: rustls inserts them in
/// turn after making the real shares, so every entry before that place is
/// already there.
fn raw_key_shares(
    profile: &UtlsClientHelloProfile,
    draws: &HelloDraws,
) -> Result<Option<ClientHelloRawKeyShares>, RustlsError> {
    let mut raw_key_shares = Vec::new();

    for (position, key_share) in profile.key_shares.iter().enumerate() {
        if is_grease_value(key_share.group) {
            raw_key_shares.push(ClientHelloRawKeyShare::new_at(
                position,
                NamedGroup::from(draws.grease(GREASE_GROUP)),
                vec![0],
            )?);
            continue;
        }

        if real_key_share_group(key_share.group).is_some() {
            continue;
        }

        raw_key_shares.push(ClientHelloRawKeyShare::new_at(
            position,
            NamedGroup::from(key_share.group),
            vec![0; key_share.key_exchange_len],
        )?);
    }

    if raw_key_shares.is_empty() {
        Ok(None)
    } else {
        ClientHelloRawKeyShares::try_from(raw_key_shares).map(Some)
    }
}

fn alpn_protocols(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloAlpnProtocols, RustlsError> {
    ClientHelloAlpnProtocols::try_from(
        profile
            .alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect::<Vec<_>>(),
    )
}

fn certificate_compression(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloCertificateCompressionAlgorithms, RustlsError> {
    ClientHelloCertificateCompressionAlgorithms::try_from(
        profile
            .certificate_compression_algorithms
            .iter()
            .filter_map(|algorithm| supported_certificate_compression(*algorithm))
            .collect::<Vec<_>>(),
    )
}

/// Restricts a rustls config to the certificate compression algorithms the
/// selected profile actually advertises and this build can decode.
pub(crate) fn retain_profile_certificate_decompressors(
    profile: &UtlsClientHelloProfile,
    decompressors: &mut Vec<&'static dyn rustls::compress::CertDecompressor>,
) {
    if profile
        .certificate_compression_algorithms
        .contains(&ZSTD_CERTIFICATE_COMPRESSION)
        && !decompressors
            .iter()
            .any(|decompressor| u16::from(decompressor.algorithm()) == ZSTD_CERTIFICATE_COMPRESSION)
    {
        decompressors.push(&ZstdCertificateDecompressor);
    }
    decompressors.retain(|decompressor| {
        let algorithm = u16::from(decompressor.algorithm());
        profile
            .certificate_compression_algorithms
            .contains(&algorithm)
            && supported_certificate_compression(algorithm).is_some()
    });
}

#[derive(Debug)]
struct ZstdCertificateDecompressor;

impl rustls::compress::CertDecompressor for ZstdCertificateDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        match zstd::bulk::decompress_to_buffer(input, output) {
            Ok(written) if written == output.len() => Ok(()),
            _ => Err(rustls::compress::DecompressionFailed),
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

/// Replaces the profile's own ALPN list with a configured one.
///
/// A profile that carries no ALPN extension needs more than a new list: the
/// extension is suppressed by the profile's extension plan, and rustls rejects
/// an extension order that omits an emitted extension, so appending ALPN to
/// the hello means un-suppressing *and* ordering it in the same breath.
///
/// Xray appends it last (`tls.go`'s `if !hasALPNExtension`) and the order
/// pinned here matches.
/// Builds the pinned extension order: the profile's own order, plus whatever
/// rustls emits on top of it.
///
/// GREASE is left out on purpose -- `grease_plan` re-inserts it by position,
/// counted against the non-GREASE extensions, so listing it here would place
/// it twice.
///
/// The order has to name every extension rustls emits, or rustls rejects it.
/// That is why `supported_versions` is appended for TLS-1.2-era profiles that
/// never declared it: rustls builds that extension into every ClientHello --
/// even a TLS-1.2-only one, where it carries just `0x0303` -- and neither the
/// extension plan (which calls it required) nor the finalizer (which may only
/// rewrite the legacy session id) can take it back out. Appending it keeps the
/// whole of uTLS' real order intact as a prefix and confines the one extension
/// we cannot suppress to the tail.
fn extension_order(
    profile: &UtlsClientHelloProfile,
    extensions: &[u16],
) -> Result<ClientHelloExtensionOrder, RustlsError> {
    let mut order = extensions
        .iter()
        .copied()
        .filter(|extension_type| !is_grease_value(*extension_type))
        .collect::<Vec<_>>();
    if !profile_has_extension(profile, EXT_SUPPORTED_VERSIONS) {
        order.push(EXT_SUPPORTED_VERSIONS);
    }

    ClientHelloExtensionOrder::try_from(order)
}

fn extension_plan(
    profile: &UtlsClientHelloProfile,
    appended_alpn: bool,
) -> Result<ClientHelloExtensionPlan, RustlsError> {
    let disabled = STRUCTURED_OPTIONAL_EXTENSIONS
        .iter()
        .copied()
        .filter(|extension_type| !profile_has_extension(profile, *extension_type))
        .filter(|extension_type| {
            *extension_type != EXT_CERTIFICATE_COMPRESSION
                || !profile_has_supported_certificate_compression(profile)
        })
        .filter(|extension_type| !appended_alpn || *extension_type != EXT_ALPN)
        .collect::<Vec<_>>();

    ClientHelloExtensionPlan::try_from(disabled)
}

fn forced_extensions(profile: &UtlsClientHelloProfile) -> ClientHelloForcedExtensions {
    let mut forced = ClientHelloForcedExtensions::new();
    if profile_has_extension(profile, EXT_RENEGOTIATION_INFO) {
        forced = forced.with_renegotiation_info_empty();
    }
    if profile_has_extension(profile, EXT_SESSION_TICKET) {
        forced = forced.with_session_ticket_request();
    }
    if profile_has_extension(profile, EXT_SIGNED_CERTIFICATE_TIMESTAMP) {
        forced = forced.with_signed_certificate_timestamp_empty();
    }
    forced
}

fn extension_payloads(
    profile: &UtlsClientHelloProfile,
    draws: &HelloDraws,
) -> Result<
    (
        Option<ClientHelloExactExtensions>,
        Option<ClientHelloRawExtensions>,
    ),
    RustlsError,
> {
    let mut exact_extensions = Vec::new();
    let mut raw_extensions = Vec::new();

    if profile_has_extension(profile, EXT_SIGNATURE_ALGORITHMS) {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_SIGNATURE_ALGORITHMS,
            signature_algorithms_payload(
                &draws.regrease(profile.signature_algorithms, GREASE_SIGNATURE_ALGORITHM),
            )?,
        )?);
    }
    if profile_has_extension(profile, EXT_DELEGATED_CREDENTIALS) {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            EXT_DELEGATED_CREDENTIALS,
            signature_algorithms_payload(profile.delegated_credentials_algorithms)?,
        )?;
    }
    if !profile_certificate_compression_is_fully_supported(profile)
        && profile_has_extension(profile, EXT_CERTIFICATE_COMPRESSION)
    {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_CERTIFICATE_COMPRESSION,
            certificate_compression_payload(profile.certificate_compression_algorithms)?,
        )?);
    }
    if let Some(record_size_limit) = profile.record_size_limit {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            EXT_RECORD_SIZE_LIMIT,
            record_size_limit.to_be_bytes().to_vec(),
        )?;
    }
    if profile.encrypted_client_hello.is_some() {
        let ech = draws.ech.ok_or_else(|| {
            RustlsError::General("encrypted_client_hello was not drawn for this hello".into())
        })?;
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_ENCRYPTED_CLIENT_HELLO,
            encrypted_client_hello_body(ech)?,
        )?);
    }
    if !profile.trust_anchor_ids.is_empty() {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            EXT_TRUST_ANCHORS,
            trust_anchors_payload(profile.trust_anchor_ids)?,
        )?;
    }
    for application_settings in profile.application_settings {
        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            application_settings.extension_type,
            application_settings_payload(application_settings.protocols)?,
        )?;
    }
    for extension in profile.extensions {
        if is_grease_value(extension.extension_type)
            || is_structured_extension(profile, extension.extension_type)
            || extension.extension_type == EXT_SIGNATURE_ALGORITHMS
            || extension.extension_type == EXT_DELEGATED_CREDENTIALS
            || extension.extension_type == EXT_CERTIFICATE_COMPRESSION
            || extension.extension_type == EXT_RECORD_SIZE_LIMIT
            || extension.extension_type == EXT_ENCRYPTED_CLIENT_HELLO
            || extension.extension_type == EXT_TRUST_ANCHORS && !profile.trust_anchor_ids.is_empty()
            || profile
                .application_settings
                .iter()
                .any(|settings| settings.extension_type == extension.extension_type)
        {
            continue;
        }

        push_exact_or_raw_extension(
            &mut exact_extensions,
            &mut raw_extensions,
            extension.extension_type,
            vec![0; extension.payload_len],
        )?;
    }

    let exact_extensions = if exact_extensions.is_empty() {
        None
    } else {
        Some(ClientHelloExactExtensions::try_from(exact_extensions)?)
    };
    let raw_extensions = if raw_extensions.is_empty() {
        None
    } else {
        Some(ClientHelloRawExtensions::try_from(raw_extensions)?)
    };

    Ok((exact_extensions, raw_extensions))
}

/// An ECH GREASE body of `grease`'s, with its cipher suite and length drawn
/// here: what ChromeParrot's QUIC hello sends. The TCP profiles draw them
/// with the rest of a hello's draws (`HelloDraws`).
pub(crate) fn encrypted_client_hello_payload(
    grease: &UtlsEchGrease,
) -> Result<Vec<u8>, RustlsError> {
    encrypted_client_hello_body(EchDraw::draw(grease)?)
}

/// Builds the ECH GREASE body uTLS's `GREASEEncryptedClientHelloExtension`
/// writes: an `ECHClientHelloOuter` carrying a freshly generated X25519 HPKE
/// encapsulated key and a random payload.
///
/// The drawn length is the whole body, and the payload is whatever the fixed
/// outer header leaves of it. Chrome's 186 leaves 144 -- uTLS
/// `BoringGREASEECH` draws 128 from `CandidatePayloadLens` and the AEAD tag
/// adds 16 -- and its 282 leaves 240, from 224; Firefox's 281 leaves 239, from
/// its own `{223}`.
///
/// Every field uTLS draws per connection is drawn here too: config id,
/// encapsulated key, and payload, next to the cipher suite and length `draw`
/// carries. Real ECH GREASE is indistinguishable from a real outer ECH
/// precisely because those are high-entropy, so filler would give a parser
/// that reads past the length prefixes something to match on. One draw covers
/// a HelloRetryRequest as well, because the plan this lands in is built once
/// per connection and reused for the second flight -- the reuse rule uTLS
/// states for the same fields.
fn encrypted_client_hello_body(draw: EchDraw) -> Result<Vec<u8>, RustlsError> {
    const OUTER_TYPE: u8 = 0;
    const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;

    let EchDraw { aead_id, length } = draw;
    // Type, KDF id, AEAD id, config id, and the two length prefixes, plus the
    // X25519 encapsulated key those prefixes bracket.
    const OUTER_HEADER_LEN: usize = 10 + ENCAPSULATED_KEY_LEN;
    // The payload is an AEAD ciphertext, so it can never be shorter than its
    // tag; `cipherLen` in uTLS adds exactly this to the drawn length.
    const AEAD_TAG_LEN: usize = 16;

    let payload_len = length
        .checked_sub(OUTER_HEADER_LEN)
        .filter(|payload_len| *payload_len >= AEAD_TAG_LEN)
        .ok_or_else(|| {
            RustlsError::General("encrypted_client_hello payload is too short".into())
        })?;
    let encoded_payload_len = u16::try_from(payload_len).map_err(|_| {
        RustlsError::General("encrypted_client_hello payload cannot exceed 65535 bytes".into())
    })?;

    let mut config_id = [0; 1];
    let mut encapsulated_key_secret = [0; ENCAPSULATED_KEY_LEN];
    let mut encrypted_payload = vec![0; payload_len];
    for bytes in [
        config_id.as_mut_slice(),
        encapsulated_key_secret.as_mut_slice(),
        encrypted_payload.as_mut_slice(),
    ] {
        OsRng.try_fill_bytes(bytes).map_err(|error| {
            RustlsError::General(format!("encrypted_client_hello needs randomness: {error}"))
        })?;
    }
    let encapsulated_key =
        X25519PublicKey::from(&X25519StaticSecret::from(encapsulated_key_secret)).to_bytes();
    encapsulated_key_secret.zeroize();

    let mut body = Vec::with_capacity(length);
    body.push(OUTER_TYPE);
    body.extend_from_slice(&HPKE_KDF_HKDF_SHA256.to_be_bytes());
    body.extend_from_slice(&aead_id.to_be_bytes());
    body.push(config_id[0]);
    body.extend_from_slice(&(ENCAPSULATED_KEY_LEN as u16).to_be_bytes());
    body.extend_from_slice(&encapsulated_key);
    body.extend_from_slice(&encoded_payload_len.to_be_bytes());
    body.extend_from_slice(&encrypted_payload);
    debug_assert_eq!(body.len(), length);
    Ok(body)
}

/// Picks one candidate uniformly, the way uTLS picks an index with
/// `rand.Int(rand.Reader, len)`.
///
/// The multiply-shift keeps the pick uniform without the modulo bias a `%` would
/// carry for a candidate count that is not a power of two.
fn draw_candidate<T: Copy>(candidates: &[T], what: &str) -> Result<T, RustlsError> {
    match candidates {
        [] => Err(RustlsError::General(format!("{what} has no candidates"))),
        [only] => Ok(*only),
        many => {
            let mut entropy = [0; 4];
            OsRng.try_fill_bytes(&mut entropy).map_err(|error| {
                RustlsError::General(format!("{what} needs randomness: {error}"))
            })?;
            let index =
                ((u64::from(u32::from_le_bytes(entropy)) * many.len() as u64) >> 32) as usize;
            Ok(many[index])
        }
    }
}

fn grease_plan(
    profile: &UtlsClientHelloProfile,
    context: ClientHelloContext<'_>,
    draws: &HelloDraws,
    extensions: &[u16],
) -> Result<Option<ClientHelloGreasePlan>, RustlsError> {
    let has_grease = profile
        .cipher_suites
        .iter()
        .chain(profile.key_shares.iter().map(|key_share| &key_share.group))
        .chain(
            profile
                .extensions
                .iter()
                .map(|extension| &extension.extension_type),
        )
        .any(|value| is_grease_value(*value));
    if !has_grease {
        return Ok(None);
    }

    // The plan's own value goes only into the cipher suites: the GREASE key
    // share is a raw one with the group slot's value, and supported_versions
    // and supported_groups carry theirs in the advertised lists.
    let mut grease = ClientHelloGreasePlan::new(draws.grease(GREASE_CIPHER))?;
    if let Some(grease_index) = profile
        .cipher_suites
        .iter()
        .position(|suite| is_grease_value(*suite))
    {
        let supported_versions = supported_versions(profile)?;
        let position = profile.cipher_suites[..grease_index]
            .iter()
            .filter(|suite| {
                provider_supports_cipher_suite(**suite, context, supported_versions.as_slice())
            })
            .count();
        grease = grease.with_cipher_suite_position(position);
    }
    let mut non_grease_position = 0;
    let mut grease_extensions = 0;
    for &extension_type in extensions {
        if !is_grease_value(extension_type) {
            non_grease_position += 1;
            continue;
        }
        // uTLS fills the first GREASE extension from one slot and the second
        // from another, and takes no third.
        let slot = match grease_extensions {
            0 => GREASE_EXTENSION1,
            1 => GREASE_EXTENSION2,
            _ => {
                return Err(RustlsError::General(
                    "a uTLS profile carries at most two GREASE extensions".into(),
                ))
            }
        };
        grease_extensions += 1;
        let payload_len = profile
            .extensions
            .iter()
            .find(|extension| extension.extension_type == extension_type)
            .map_or(0, |extension| extension.payload_len);
        grease = grease.with_extension(ClientHelloGreaseExtension::new(
            draws.grease(slot),
            non_grease_position,
            vec![0; payload_len],
        )?)?;
    }

    Ok(Some(grease))
}

pub(crate) fn signature_algorithms_payload(algorithms: &[u16]) -> Result<Vec<u8>, RustlsError> {
    let byte_len = algorithms
        .len()
        .checked_mul(2)
        .ok_or_else(|| RustlsError::General("signature_algorithms payload is too large".into()))?;
    let byte_len = u16::try_from(byte_len).map_err(|_| {
        RustlsError::General("signature_algorithms payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(2 + usize::from(byte_len));
    payload.extend_from_slice(&byte_len.to_be_bytes());
    for algorithm in algorithms {
        payload.extend_from_slice(&algorithm.to_be_bytes());
    }
    Ok(payload)
}

fn certificate_compression_payload(algorithms: &[u16]) -> Result<Vec<u8>, RustlsError> {
    let byte_len = algorithms
        .len()
        .checked_mul(2)
        .ok_or_else(|| RustlsError::General("compress_certificate payload is too large".into()))?;
    let byte_len = u8::try_from(byte_len).map_err(|_| {
        RustlsError::General("compress_certificate payload cannot exceed 255 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(1 + usize::from(byte_len));
    payload.push(byte_len);
    for algorithm in algorithms {
        payload.extend_from_slice(&algorithm.to_be_bytes());
    }
    Ok(payload)
}

/// uTLS's `TrustAnchorsExtension` body: the IDs, each behind a one-byte
/// length, behind a two-byte length of them all.
fn trust_anchors_payload(ids: &[&[u8]]) -> Result<Vec<u8>, RustlsError> {
    let list_len = ids.iter().try_fold(0usize, |total, id| {
        let id_len = u8::try_from(id.len())
            .ok()
            .filter(|len| *len > 0)
            .ok_or_else(|| RustlsError::General("a trust anchor ID takes 1 to 255 bytes".into()))?;
        total
            .checked_add(1 + usize::from(id_len))
            .ok_or_else(|| RustlsError::General("trust_anchors payload is too large".into()))
    })?;
    let list_len = u16::try_from(list_len).map_err(|_| {
        RustlsError::General("trust_anchors payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(2 + usize::from(list_len));
    payload.extend_from_slice(&list_len.to_be_bytes());
    for id in ids {
        payload.push(id.len() as u8);
        payload.extend_from_slice(id);
    }
    Ok(payload)
}

pub(crate) fn application_settings_payload(protocols: &[&[u8]]) -> Result<Vec<u8>, RustlsError> {
    let protocols_len = protocols.iter().try_fold(0usize, |total, protocol| {
        if protocol.len() > usize::from(u8::MAX) {
            return Err(RustlsError::General(
                "application_settings protocol name cannot exceed 255 bytes".into(),
            ));
        }
        total
            .checked_add(1 + protocol.len())
            .ok_or_else(|| RustlsError::General("application_settings payload is too large".into()))
    })?;
    let protocols_len = u16::try_from(protocols_len).map_err(|_| {
        RustlsError::General("application_settings payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(2 + usize::from(protocols_len));
    payload.extend_from_slice(&protocols_len.to_be_bytes());
    for protocol in protocols {
        payload.push(protocol.len() as u8);
        payload.extend_from_slice(protocol);
    }
    Ok(payload)
}

pub(crate) fn push_exact_or_raw_extension(
    exact_extensions: &mut Vec<ClientHelloExactExtension>,
    raw_extensions: &mut Vec<ClientHelloRawExtension>,
    extension_type: u16,
    payload: Vec<u8>,
) -> Result<(), RustlsError> {
    match ClientHelloRawExtension::new(extension_type, payload.clone()) {
        Ok(extension) => {
            raw_extensions.push(extension);
            Ok(())
        }
        Err(_) => {
            exact_extensions.push(ClientHelloExactExtension::new(extension_type, payload)?);
            Ok(())
        }
    }
}

fn is_structured_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    matches!(
        extension_type,
        EXT_SERVER_NAME
            | EXT_STATUS_REQUEST
            | EXT_SUPPORTED_GROUPS
            | EXT_EC_POINT_FORMATS
            | EXT_ALPN
            | EXT_SIGNED_CERTIFICATE_TIMESTAMP
            | EXT_PADDING
            | EXT_EXTENDED_MASTER_SECRET
            | EXT_SESSION_TICKET
            | EXT_SUPPORTED_VERSIONS
            | EXT_PSK_KEY_EXCHANGE_MODES
            | EXT_KEY_SHARE
            | EXT_RENEGOTIATION_INFO
    ) || extension_type == EXT_CERTIFICATE_COMPRESSION
        && profile_has_supported_certificate_compression(profile)
}

fn profile_has_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    profile
        .extensions
        .iter()
        .any(|extension| extension.extension_type == extension_type)
}

fn profile_has_supported_certificate_compression(profile: &UtlsClientHelloProfile) -> bool {
    profile
        .certificate_compression_algorithms
        .iter()
        .any(|algorithm| supported_certificate_compression(*algorithm).is_some())
}

fn profile_certificate_compression_is_fully_supported(profile: &UtlsClientHelloProfile) -> bool {
    !profile.certificate_compression_algorithms.is_empty()
        && profile
            .certificate_compression_algorithms
            .iter()
            .all(|algorithm| supported_certificate_compression(*algorithm).is_some())
}

fn supported_certificate_compression(algorithm: u16) -> Option<CertificateCompressionAlgorithm> {
    match algorithm {
        ZLIB_CERTIFICATE_COMPRESSION => Some(CertificateCompressionAlgorithm::Zlib),
        BROTLI_CERTIFICATE_COMPRESSION => Some(CertificateCompressionAlgorithm::Brotli),
        ZSTD_CERTIFICATE_COMPRESSION => Some(CertificateCompressionAlgorithm::Zstd),
        _ => None,
    }
}

fn real_supported_group(group: u16) -> Option<NamedGroup> {
    match group {
        GROUP_X25519 => Some(NamedGroup::X25519),
        GROUP_X25519_MLKEM768 => Some(NamedGroup::X25519MLKEM768),
        GROUP_X25519_MLKEM768_DRAFT => Some(NamedGroup::Unknown(GROUP_X25519_MLKEM768_DRAFT)),
        GROUP_SECP256R1 => Some(NamedGroup::secp256r1),
        GROUP_SECP384R1 => Some(NamedGroup::secp384r1),
        _ => None,
    }
}

fn real_key_share_group(group: u16) -> Option<NamedGroup> {
    match group {
        GROUP_X25519 => Some(NamedGroup::X25519),
        GROUP_X25519_MLKEM768 => Some(NamedGroup::X25519MLKEM768),
        GROUP_X25519_MLKEM768_DRAFT => Some(NamedGroup::Unknown(GROUP_X25519_MLKEM768_DRAFT)),
        GROUP_SECP256R1 => Some(NamedGroup::secp256r1),
        _ => None,
    }
}

fn is_grease_value(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::utls_profiles::{ECH_GREASE_BORING, ECH_GREASE_FIREFOX};

    /// The fingerprints whose uTLS spec runs `ShuffleChromeTLSExtensions`
    /// (`u_parrots.go`), with Chrome 155's two other names.
    const SHUFFLED: [&str; 12] = [
        "chrome",
        "hellochrome_auto",
        "hellochrome_106_shuffle",
        "hellochrome_112_psk_shuf",
        "hellochrome_114_padding_psk_shuf",
        "hellochrome_115_pq",
        "hellochrome_115_pq_psk",
        "hellochrome_120",
        "hellochrome_120_pq",
        "hellochrome_131",
        "hellochrome_133",
        "hellochrome_155",
    ];

    fn profile(name: &str) -> &'static UtlsClientHelloProfile {
        crate::utls_profiles::profile_for_fingerprint(name)
            .unwrap_or_else(|| panic!("{name}: no profile"))
    }

    fn recorded_order(profile: &UtlsClientHelloProfile) -> Vec<u16> {
        profile
            .extensions
            .iter()
            .map(|extension| extension.extension_type)
            .collect()
    }

    fn random_seed() -> i64 {
        loop {
            let mut bytes = [0; 8];
            OsRng.fill_bytes(&mut bytes);
            if let Some(seed) = crypto_rand_int63(bytes) {
                return seed;
            }
        }
    }

    #[test]
    fn exactly_the_shuffling_specs_shuffle() {
        for name in xray_utls::XRAY_UTLS_FINGERPRINTS {
            if matches!(*name, "random" | "randomized") {
                continue;
            }
            let Some(profile) = crate::utls_profiles::profile_for_fingerprint(name) else {
                continue;
            };
            assert_eq!(
                !profile.unshuffled_extensions.is_empty(),
                SHUFFLED.contains(name),
                "{name}"
            );
        }
    }

    /// uTLS's own output: the oracle fixtures are made under an all-zero
    /// `crypto/rand`, whose shuffle seed is 0, and each spec order shuffled
    /// with it, less the padding and pre_shared_key the hello leaves out, is
    /// the order its fixture records.
    #[test]
    fn the_zero_seed_shuffles_each_spec_into_its_fixture_order() {
        for name in SHUFFLED {
            let profile = profile(name);
            assert_eq!(
                HelloDraws::zero(profile).extension_types(profile),
                recorded_order(profile),
                "{name}"
            );
        }
    }

    /// What stays where the spec puts it: the two GREASE extensions, padding
    /// and pre_shared_key. Every other extension reaches every other place:
    /// the rarest pairing comes up in about one draw in twenty, so a thousand
    /// draws miss one with odds below 10^-18.
    #[test]
    fn the_shuffle_keeps_grease_padding_and_psk_in_place() {
        for name in SHUFFLED {
            let spec = profile(name).unshuffled_extensions;
            let mut seen = HashSet::new();
            for _ in 0..1000 {
                let order = chrome_shuffle(spec, random_seed());
                let mut sorted = order.clone();
                sorted.sort_unstable();
                let mut expected = spec.to_vec();
                expected.sort_unstable();
                assert_eq!(
                    sorted, expected,
                    "{name}: the shuffle moves nothing in or out"
                );
                for (place, (now, was)) in order.iter().zip(spec).enumerate() {
                    if stays_in_place(*was) {
                        assert_eq!(now, was, "{name}: {was:#06x} left place {place}");
                    } else {
                        seen.insert((*now, place));
                    }
                }
            }
            let movable = spec
                .iter()
                .filter(|extension| !stays_in_place(**extension))
                .count();
            assert_eq!(seen.len(), movable * movable, "{name}");
        }
    }

    /// `getBoringGREASEValue` on uTLS's little-endian seeds, the second
    /// GREASE extension moved off the first's value, and each slot drawn on
    /// its own.
    #[test]
    fn grease_takes_boringssl_values_from_the_seeds() {
        assert_eq!(boring_grease(0x0000), 0x0a0a);
        assert_eq!(boring_grease(0x00f0), 0xfafa);
        assert_eq!(boring_grease(0xab35), 0x3a3a);
        assert_eq!(boring_grease(0xff0f), 0x0a0a);

        let chrome = profile("hellochrome_155");
        assert_eq!(
            HelloDraws::zero(chrome).grease,
            [0x0a0a, 0x0a0a, 0x0a0a, 0x1a1a, 0x0a0a, 0x0a0a, 0x0a0a, 0x0a0a]
        );
        let mut seeds = [0; 2 * GREASE_SEEDS];
        seeds[0] = 0x35;
        seeds[1] = 0xab;
        seeds[2] = 0x70;
        seeds[4] = 0xc0;
        seeds[6] = 0xc0;
        seeds[8] = 0x10;
        seeds[14] = 0xe5;
        assert_eq!(
            HelloDraws::from_seeds(chrome, seeds, None, None).grease,
            [0x3a3a, 0x7a7a, 0xcaca, 0xdada, 0x1a1a, 0x0a0a, 0x0a0a, 0xeaea]
        );

        let mut values = vec![HashSet::new(); GREASE_SEEDS];
        for _ in 0..2000 {
            let draws = HelloDraws::draw(chrome).unwrap();
            assert_ne!(
                draws.grease(GREASE_EXTENSION1),
                draws.grease(GREASE_EXTENSION2)
            );
            for (slot, value) in draws.grease.iter().enumerate() {
                assert!(is_grease_value(*value));
                values[slot].insert(*value);
            }
        }
        for slot in [
            GREASE_CIPHER,
            GREASE_GROUP,
            GREASE_EXTENSION1,
            GREASE_EXTENSION2,
            GREASE_VERSION,
            GREASE_SIGNATURE_ALGORITHM,
        ] {
            assert_eq!(values[slot].len(), 16, "slot {slot}");
        }
    }

    /// Fixed draws fail this: every hello of a shuffling profile draws its
    /// own order and GREASE values, and a profile with a fixed order keeps it
    /// while its GREASE values still change.
    #[test]
    fn each_hello_draws_anew() {
        for name in SHUFFLED {
            let profile = profile(name);
            let draws = (0..64)
                .map(|_| HelloDraws::draw(profile).unwrap())
                .collect::<Vec<_>>();
            let orders = draws
                .iter()
                .map(|draws| draws.extension_types(profile))
                .collect::<HashSet<_>>();
            let grease = draws
                .iter()
                .map(|draws| draws.grease)
                .collect::<HashSet<_>>();
            assert!(orders.len() > 60, "{name}: {} orders", orders.len());
            assert!(grease.len() > 60, "{name}: {} GREASE draws", grease.len());
        }
        let safari = profile("safari");
        let draws = (0..64)
            .map(|_| HelloDraws::draw(safari).unwrap())
            .collect::<Vec<_>>();
        assert!(draws
            .iter()
            .all(|draws| draws.extension_types(safari) == recorded_order(safari)));
        assert!(
            draws
                .iter()
                .map(|draws| draws.grease)
                .collect::<HashSet<_>>()
                .len()
                > 60
        );
    }

    /// Every committed uTLS hello made with `-raw`, each ECH GREASE length of
    /// each Chrome profile among them.
    const RAW_ORACLE_HELLOS: [&str; 29] = [
        include_str!("../../../tests/fixtures/reality/clienthello_raw_chrome.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_chrome_ech160.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_chrome_ech192.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_chrome_ech224.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_133.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_133_ech160.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_133_ech192.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_133_ech224.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_pq.json"),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_pq_ech160.json"
        ),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_pq_ech192.json"
        ),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_pq_ech224.json"
        ),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_120.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_ech160.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_ech192.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_120_ech224.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_131.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_131_ech160.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_131_ech192.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellochrome_131_ech224.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_helloios_13.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hello360_11_0.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_63.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_65.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_99.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_102.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_105.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_120.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_raw_hellofirefox_auto.json"),
    ];

    /// Every committed uTLS hello shape, the `http/1.1` override's among them.
    const ORACLE_SHAPES: [&str; 9] = [
        include_str!("../../../tests/fixtures/reality/clienthello_shape_hellochrome_100.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_shape_hellochrome_58.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_shape_android.json"),
        include_str!("../../../tests/fixtures/reality/clienthello_shape_randomizednoalpn.json"),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn.json"
        ),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn_ech160.json"
        ),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn_ech192.json"
        ),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_shape_chrome_websocket_alpn_ech224.json"
        ),
        include_str!(
            "../../../tests/fixtures/reality/clienthello_shape_android_websocket_alpn.json"
        ),
    ];

    #[test]
    fn hello_draws_take_each_ech_length_of_the_scheme() {
        let chrome = profile("hellochrome_133");
        let lengths = (0..400)
            .map(|_| HelloDraws::draw(chrome).unwrap().ech.unwrap().length)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(lengths, [186, 218, 250, 282].into_iter().collect());
        assert_eq!(
            HelloDraws::zero(chrome).ech,
            Some(EchDraw {
                aead_id: crate::utls_profiles::HPKE_AEAD_AES_128_GCM,
                length: 186,
            }),
            "an all-zero crypto/rand picks the first length"
        );

        let firefox = profile("hellofirefox_120");
        assert!((0..64).all(|_| HelloDraws::draw(firefox).unwrap().ech.unwrap().length == 281));
        assert_eq!(
            HelloDraws::draw(profile("hellochrome_100")).unwrap().ech,
            None
        );
    }

    /// What a padding extension adds before its body: type and length.
    const EXTENSION_HEADER_LEN: usize = 4;

    /// A ClientHello handshake message's cipher suite count and its
    /// extensions as type and body length, in order.
    fn hello_layout(hello: &[u8]) -> (usize, Vec<(u16, usize)>) {
        let u16_at = |at: usize| usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        let mut cursor = 4 + 2 + 32;
        cursor += 1 + usize::from(hello[cursor]);
        let cipher_suites = u16_at(cursor) / 2;
        cursor += 2 + 2 * cipher_suites;
        cursor += 1 + usize::from(hello[cursor]);
        let end = cursor + 2 + u16_at(cursor);
        cursor += 2;
        let mut extensions = Vec::new();
        while cursor < end {
            let body = u16_at(cursor + 2);
            extensions.push((u16_at(cursor) as u16, body));
            cursor += 4 + body;
        }
        assert_eq!(cursor, hello.len(), "the extensions end the hello");
        (cipher_suites, extensions)
    }

    /// The body length of the `wanted` extension in a hello's layout.
    fn body_len(extensions: &[(u16, usize)], wanted: u16) -> Option<usize> {
        extensions
            .iter()
            .find(|(extension_type, _)| *extension_type == wanted)
            .map(|(_, body)| *body)
    }

    /// A hello's length without its padding extension.
    fn unpadded(hello_len: usize, padding: Option<usize>) -> usize {
        hello_len - padding.map_or(0, |padding| EXTENSION_HEADER_LEN + padding)
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    }

    /// A plain-TLS hello of `fingerprint` to example.com whose ECH GREASE
    /// extension is `ech` long: hellos are made until one draws it.
    fn hello_with_ech(fingerprint: &str, websocket_alpn: bool, ech: Option<usize>) -> Vec<u8> {
        let config = crate::TlsClientConfig {
            server_name: "example.com".to_owned(),
            allow_insecure: true,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: if websocket_alpn {
                vec!["http/1.1".to_owned()]
            } else {
                Vec::new()
            },
            fingerprint: Some(fingerprint.to_owned()),
        };
        for _ in 0..256 {
            let record = crate::tls::plain_tls_client_hello_bytes(&config)
                .unwrap_or_else(|error| panic!("{fingerprint}: ClientHello: {error}"));
            let hello = record[5..].to_vec();
            let (_, extensions) = hello_layout(&hello);
            if body_len(&extensions, EXT_ENCRYPTED_CLIENT_HELLO) == ech {
                return hello;
            }
        }
        panic!("{fingerprint}: no hello in 256 drew the ECH length {ech:?}");
    }

    /// `boringssl_padding_offset` for a profile as the plain-TLS path shapes it:
    /// the shaping provider's suites, and TLS 1.2 alone for a TLS-1.2-era
    /// profile.
    fn padding_offset(profile: &UtlsClientHelloProfile) -> isize {
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
        let tls12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
        let context = ClientHelloContext {
            server_name: &server_name,
            alpn_protocols: &[],
            versions: if profile_offers_tls13(profile) {
                rustls::ALL_VERSIONS
            } else {
                tls12
            },
            crypto_provider: &provider,
            is_quic: false,
        };
        let supported_versions = supported_versions(profile).unwrap();
        boringssl_padding_offset(profile, context, supported_versions.as_slice())
    }

    #[test]
    fn the_padding_offset_counts_filtered_suites_and_the_added_supported_versions() {
        // Six suites rustls lacks (CBC and RSA key exchange), the twelve bytes
        // Chrome 120's padding makes up against uTLS's fixtures.
        assert_eq!(padding_offset(profile("hellochrome_120")), 12);

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        for name in ["hellofirefox_120", "hellochrome_133", "hellochrome_58"] {
            let profile = profile(name);
            let tls13 = profile_offers_tls13(profile);
            let filtered = profile
                .cipher_suites
                .iter()
                .filter(|suite| !is_grease_value(**suite))
                .filter(|suite| {
                    !provider.cipher_suites.iter().any(|candidate| {
                        u16::from(candidate.suite()) == **suite
                            && (tls13 || candidate.version().version == ProtocolVersion::TLSv1_2)
                    })
                })
                .count() as isize;
            // A TLS-1.2-era hello also carries the seven-byte
            // supported_versions rustls adds and uTLS's lacks.
            let added = if tls13 { 0 } else { 7 };
            assert_eq!(padding_offset(profile), 2 * filtered - added, "{name}");
        }
        assert!(!profile_offers_tls13(profile("hellochrome_58")));
    }

    /// Our hello plus `boringssl_padding_offset` is uTLS's own hello before
    /// padding, for every committed oracle hello: each ECH length of each
    /// Chrome profile, and the `http/1.1` override's shapes. That is the
    /// length shaped-rustls hands BoringSSL's rule on every flight.
    #[test]
    fn the_padding_offset_brings_our_hellos_to_utls_lengths() {
        for fixture in RAW_ORACLE_HELLOS {
            let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
            let name = fixture["fingerprint"].as_str().unwrap();
            assert_eq!(fixture["server_name"], "example.com");
            let utls = decode_hex(fixture["client_hello_hex"].as_str().unwrap());
            let (_, utls_extensions) = hello_layout(&utls);
            let ech = body_len(&utls_extensions, EXT_ENCRYPTED_CLIENT_HELLO);
            let ours = hello_with_ech(name, false, ech);
            let (_, our_extensions) = hello_layout(&ours);
            assert_eq!(
                unpadded(ours.len(), body_len(&our_extensions, EXT_PADDING)) as isize
                    + padding_offset(profile(name)),
                unpadded(utls.len(), body_len(&utls_extensions, EXT_PADDING)) as isize,
                "{name} (ECH {ech:?})"
            );
        }
        for shape in ORACLE_SHAPES {
            let shape: serde_json::Value = serde_json::from_str(shape).unwrap();
            let name = shape["fingerprint"].as_str().unwrap();
            assert_eq!(shape["server_name"], "example.com");
            let length = |key: &str| shape[key].as_u64().map(|value| value as usize);
            let ech = length("encrypted_client_hello_length");
            let websocket_alpn = shape["websocket_alpn"].as_bool().unwrap_or(false);
            let ours = hello_with_ech(name, websocket_alpn, ech);
            let (_, our_extensions) = hello_layout(&ours);
            assert_eq!(
                unpadded(ours.len(), body_len(&our_extensions, EXT_PADDING)) as isize
                    + padding_offset(profile(name)),
                unpadded(
                    length("handshake_length").unwrap(),
                    length("padding_length")
                ) as isize,
                "{name} (ECH {ech:?}, websocket ALPN {websocket_alpn})"
            );
        }
    }

    /// A DNS name of exactly `len` bytes, in labels of at most 51.
    fn dns_name(len: usize) -> String {
        (0..len)
            .map(|at| {
                if at % 52 == 51 && at + 1 < len {
                    '.'
                } else {
                    'a'
                }
            })
            .collect()
    }

    /// Every padded profile pads as BoringSSL pads the hello uTLS sends on
    /// the same connection, at every length: server names of one to 253
    /// bytes walk each one across both edges of BoringSSL's window, Chrome 120
    /// with each of its four ECH lengths, with the profile's ALPN and with the
    /// `http/1.1` override; IP literals, which carry no server name, and a
    /// name with a trailing dot, which is sent without it, come on top.
    ///
    /// uTLS's length is read off our own hello, independently of
    /// `boringssl_padding_offset`: the suites the provider filtered go back
    /// in, as counted on the wire, and
    /// what rustls adds that the profile lacks (`supported_versions` on a
    /// TLS-1.2-era hello) comes out. BoringSSL's rule is restated here from
    /// `BoringPaddingStyle`.
    #[test]
    fn padded_profiles_pad_as_boringssl_pads_the_utls_hello() {
        let mut profiles: Vec<(&str, &UtlsClientHelloProfile)> = Vec::new();
        for name in xray_utls::XRAY_UTLS_FINGERPRINTS {
            if matches!(*name, "random" | "randomized") {
                continue;
            }
            let Some(profile) = crate::utls_profiles::profile_for_fingerprint(name) else {
                continue;
            };
            if profile.padding_length.is_some()
                && !profiles
                    .iter()
                    .any(|(_, seen)| std::ptr::eq(*seen, profile))
            {
                profiles.push((name, profile));
            }
        }
        assert!(profiles.iter().any(|(name, _)| *name == "hellochrome_120"));
        let server_names = (1..=253)
            .map(dns_name)
            .chain(["203.0.113.10", "2001:db8::10", "example.com."].map(str::to_owned))
            .collect::<Vec<_>>();
        let mut checked = 0;

        for (name, profile) in &profiles {
            let profile_types = profile
                .extensions
                .iter()
                .map(|extension| extension.extension_type)
                .collect::<Vec<_>>();
            let lengths = profile
                .encrypted_client_hello
                .map_or(1, |ech| ech.lengths.len());
            for (server_name, alpn) in server_names
                .iter()
                .flat_map(|server_name| [(server_name, None), (server_name, Some("http/1.1"))])
            {
                let config = crate::TlsClientConfig {
                    server_name: server_name.clone(),
                    allow_insecure: true,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: alpn.into_iter().map(str::to_owned).collect(),
                    fingerprint: Some((*name).to_owned()),
                };
                let mut ech_lengths = HashSet::new();
                for _ in 0..256 {
                    let record = crate::tls::plain_tls_client_hello_bytes(&config)
                        .unwrap_or_else(|error| panic!("{name}: ClientHello: {error}"));
                    let hello = &record[5..];
                    let (cipher_suites, extensions) = hello_layout(hello);
                    let body = |wanted: u16| {
                        extensions
                            .iter()
                            .find(|(extension_type, _)| *extension_type == wanted)
                            .map(|(_, body)| *body)
                    };
                    let padding = body(EXT_PADDING);
                    // An ALPN extension the override appends is one uTLS's
                    // hello gets too, from Xray.
                    let added = extensions
                        .iter()
                        .filter(|(extension_type, _)| {
                            *extension_type != EXT_ALPN
                                && !profile_types.iter().any(|profile_type| {
                                    profile_type == extension_type
                                        || is_grease_value(*profile_type)
                                            && is_grease_value(*extension_type)
                                })
                        })
                        .map(|(_, body)| EXTENSION_HEADER_LEN + body)
                        .sum::<usize>();
                    let utls_unpadded = unpadded(hello.len(), padding)
                        + 2 * (profile.cipher_suites.len() - cipher_suites)
                        - added;
                    let utls_padding = (0x100..0x200).contains(&utls_unpadded).then(|| {
                        // `paddingLen >= 4+1` in uTLS.
                        let padding = 0x200 - utls_unpadded;
                        if padding > 4 {
                            padding - 4
                        } else {
                            1
                        }
                    });
                    let what = format!(
                        "{name}, server name {server_name:?}, ALPN override {alpn:?}, ECH {:?}: \
                         uTLS's hello is {utls_unpadded} bytes before padding",
                        body(EXT_ENCRYPTED_CLIENT_HELLO)
                    );
                    match utls_padding {
                        None => assert_eq!(padding, None, "{what}, so it has no padding"),
                        Some(utls_padding) => {
                            assert!(padding.is_some(), "{what}, so it is padded");
                            assert_eq!(
                                hello.len(),
                                utls_unpadded + EXTENSION_HEADER_LEN + utls_padding,
                                "{what}, and ours must come to the length uTLS's does"
                            );
                        }
                    }
                    checked += 1;
                    ech_lengths.insert(body(EXT_ENCRYPTED_CLIENT_HELLO));
                    if ech_lengths.len() == lengths {
                        break;
                    }
                }
                assert_eq!(ech_lengths.len(), lengths, "{name}: every ECH length drawn");
            }
        }
        assert!(
            checked >= profiles.len() * 2 * server_names.len(),
            "{checked} hellos checked"
        );
    }

    /// The two ECH GREASE schemes the profile table records: Chrome's
    /// `BoringGREASEECH` (bodies 186, 218, 250 and 282, payloads 144 to 240)
    /// and Firefox's (`CandidatePayloadLens: []uint16{223}`, body 281,
    /// payload 239).
    const PROFILE_ECH_GREASE: [UtlsEchGrease; 2] = [ECH_GREASE_BORING, ECH_GREASE_FIREFOX];

    #[test]
    fn ech_grease_payload_matches_utls_outer_layout() {
        for grease in PROFILE_ECH_GREASE {
            let body = encrypted_client_hello_payload(&grease)
                .unwrap_or_else(|error| panic!("ECH GREASE body: {error}"));
            let length = body.len();

            assert!(
                grease.lengths.contains(&length),
                "body length {length} is one the profile can draw"
            );
            assert_eq!(body[0], 0x00, "ECHClientHelloType outer for {length}");
            assert_eq!(&body[1..3], [0x00, 0x01], "HKDF-SHA256 kdf id for {length}");
            let aead_id = u16::from_be_bytes([body[3], body[4]]);
            assert!(
                grease.aead_ids.contains(&aead_id),
                "aead {aead_id:#06x} is one the profile can draw for {length}"
            );
            assert_eq!(&body[6..8], [0x00, 0x20], "enc length for {length}");
            assert_eq!(
                &body[40..42],
                (length as u16 - 42).to_be_bytes(),
                "payload length for {length}"
            );
        }
    }

    #[test]
    fn ech_grease_payload_draws_fresh_randomness_per_call() {
        const DRAWS: usize = 32;

        let bodies = (0..DRAWS)
            .map(|_| {
                encrypted_client_hello_payload(&ECH_GREASE_BORING)
                    .expect("ECH GREASE body should be built")
            })
            .collect::<Vec<_>>();

        let config_ids = bodies.iter().map(|body| body[5]).collect::<HashSet<_>>();
        let keys = bodies
            .iter()
            .map(|body| body[8..40].to_vec())
            .collect::<HashSet<_>>();
        let payloads = bodies
            .iter()
            .map(|body| body[42..].to_vec())
            .collect::<HashSet<_>>();

        assert!(
            config_ids.len() > 1,
            "config_id is constant across {DRAWS} draws"
        );
        assert_eq!(keys.len(), DRAWS, "enc repeats across {DRAWS} draws");
        assert_eq!(
            payloads.len(),
            DRAWS,
            "payload repeats across {DRAWS} draws"
        );
        assert!(
            keys.iter().all(|key| key.iter().any(|byte| *byte != 0)),
            "enc is zero filled"
        );
        assert!(
            payloads
                .iter()
                .all(|payload| payload.iter().any(|byte| *byte != 0)),
            "payload is zero filled"
        );
    }

    #[test]
    fn ech_grease_payload_rejects_bodies_too_short_for_an_outer_hello() {
        let too_short = UtlsEchGrease {
            aead_ids: &[0x0001],
            lengths: &[57],
        };

        assert!(
            encrypted_client_hello_payload(&too_short).is_err(),
            "a 57-byte body cannot hold the 42-byte outer header and a 16-byte AEAD tag"
        );
    }

    /// uTLS's `TrustAnchorsExtension.Read`: a two-byte length of the list,
    /// then each ID behind its one-byte length.
    #[test]
    fn trust_anchors_are_written_as_utls_writes_them() {
        assert_eq!(
            super::trust_anchors_payload(&[&[0x82, 0xdf], &[0x07]]).unwrap(),
            [0x00, 0x05, 0x02, 0x82, 0xdf, 0x01, 0x07]
        );
        assert_eq!(super::trust_anchors_payload(&[]).unwrap(), [0x00, 0x00]);
        assert!(super::trust_anchors_payload(&[&[]]).is_err());
        assert!(super::trust_anchors_payload(&[&[0; 256]]).is_err());
    }
}
