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
//! declared is suppressed no matter what payload it is given, which is why
//! ALPN overrides go through `apply_alpn_override` rather than a bare
//! `.with_alpn_protocols(...)`.

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

use crate::utls_profiles::{UtlsClientHelloProfile, UtlsEchGrease};

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_CERTIFICATE_COMPRESSION: u16 = 0x001b;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_DELEGATED_CREDENTIALS: u16 = 0x0022;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
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
const BORINGSSL_PADDING_TARGET_HANDSHAKE_SIZE: usize = 512;
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

pub(crate) fn apply_utls_profile(
    mut plan: ClientHelloPlan,
    profile: &'static UtlsClientHelloProfile,
    context: ClientHelloContext<'_>,
) -> Result<ClientHelloPlan, RustlsError> {
    let supported_versions = supported_versions(profile)?;
    let cipher_suites = cipher_suites(profile, context, supported_versions.as_slice())?;
    plan = plan
        .with_cipher_suites(cipher_suites)
        .with_supported_versions(supported_versions);

    if !profile.supported_versions.is_empty() {
        plan = plan.with_advertised_supported_versions(advertised_supported_versions(profile)?);
    }
    if !profile.supported_groups.is_empty() {
        plan = plan.with_supported_groups(supported_groups(profile)?);
        plan = plan.with_advertised_supported_groups(advertised_supported_groups(profile)?);
    }
    if !profile.key_shares.is_empty() {
        plan = plan.with_key_share_plan(key_share_plan(profile)?);
    }
    if let Some(raw_key_shares) = raw_key_shares(profile)? {
        plan = plan.with_raw_key_shares(raw_key_shares);
    }
    if !profile.alpn_protocols.is_empty() {
        plan = plan.with_alpn_protocols(alpn_protocols(profile)?);
    }
    if profile_has_supported_certificate_compression(profile) {
        plan = plan.with_certificate_compression_algorithms(certificate_compression(profile)?);
    }

    let forced_extensions = forced_extensions(profile);
    let extension_plan = extension_plan(profile, false)?;
    let (exact_extensions, raw_extensions) = extension_payloads(profile)?;

    plan = plan
        .with_forced_extensions(forced_extensions)
        .with_extensions(extension_plan)
        .with_extension_order(extension_order(profile, false)?);

    if let Some(exact_extensions) = exact_extensions {
        plan = plan.with_exact_extensions(exact_extensions);
    }
    if let Some(raw_extensions) = raw_extensions {
        plan = plan.with_raw_extensions(raw_extensions);
    }
    if let Some(grease) = grease_plan(profile, context)? {
        plan = plan.with_grease(grease);
    }
    if profile.padding_length.is_some() {
        plan = plan.with_padding(ClientHelloPaddingPlan::pad_to_handshake_size(
            BORINGSSL_PADDING_TARGET_HANDSHAKE_SIZE,
        )?);
    }

    Ok(plan)
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
) -> Result<ClientHelloAdvertisedSupportedVersions, RustlsError> {
    ClientHelloAdvertisedSupportedVersions::try_from(
        profile
            .supported_versions
            .iter()
            .copied()
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
) -> Result<ClientHelloAdvertisedSupportedGroups, RustlsError> {
    ClientHelloAdvertisedSupportedGroups::try_from(
        profile
            .supported_groups
            .iter()
            .copied()
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

fn raw_key_shares(
    profile: &UtlsClientHelloProfile,
) -> Result<Option<ClientHelloRawKeyShares>, RustlsError> {
    let mut raw_key_shares = Vec::new();
    let mut non_grease_position = 0;

    for key_share in profile.key_shares {
        if is_grease_value(key_share.group) {
            continue;
        }

        if real_key_share_group(key_share.group).is_some() {
            non_grease_position += 1;
            continue;
        }

        raw_key_shares.push(ClientHelloRawKeyShare::new_at(
            non_grease_position,
            NamedGroup::from(key_share.group),
            vec![0; key_share.key_exchange_len],
        )?);
        non_grease_position += 1;
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
pub(crate) fn apply_alpn_override(
    mut plan: ClientHelloPlan,
    profile: &'static UtlsClientHelloProfile,
    protocols: &[Vec<u8>],
) -> Result<ClientHelloPlan, RustlsError> {
    plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(protocols.to_vec())?);
    if profile_has_extension(profile, EXT_ALPN) {
        return Ok(plan);
    }

    // The two must move together: un-suppressing the extension without also
    // ordering it is an error inside rustls, not a shape difference.
    plan = plan
        .with_extensions(extension_plan(profile, true)?)
        .with_extension_order(extension_order(profile, true)?);

    Ok(plan)
}

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
    appended_alpn: bool,
) -> Result<ClientHelloExtensionOrder, RustlsError> {
    let mut order = profile
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .filter(|extension_type| !is_grease_value(*extension_type))
        .collect::<Vec<_>>();
    if appended_alpn {
        order.push(EXT_ALPN);
    }
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
            signature_algorithms_payload(profile.signature_algorithms)?,
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
    if let Some(grease) = profile.encrypted_client_hello {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_ENCRYPTED_CLIENT_HELLO,
            encrypted_client_hello_payload(&grease)?,
        )?);
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

/// Builds the ECH GREASE body uTLS's `GREASEEncryptedClientHelloExtension`
/// writes: an `ECHClientHelloOuter` carrying a freshly generated X25519 HPKE
/// encapsulated key and a random payload.
///
/// `length` is the body length the profile recorded, and the payload is
/// whatever the fixed outer header leaves of it. Chrome's 186 leaves 144 --
/// uTLS `BoringGREASEECH` draws 128 from `CandidatePayloadLens` and the AEAD
/// tag adds 16 -- and Firefox's 281 leaves 239, from its own `{223}`.
///
/// Every field uTLS draws per connection is drawn here too: config id,
/// encapsulated key, and payload. Real ECH GREASE is indistinguishable from a
/// real outer ECH precisely because those are high-entropy, so filler would
/// give a parser that reads past the length prefixes something to match on.
/// One draw covers a HelloRetryRequest as well, because the plan this lands in
/// is built once per connection and reused for the second flight -- the reuse
/// rule uTLS states for the same fields.
fn encrypted_client_hello_payload(grease: &UtlsEchGrease) -> Result<Vec<u8>, RustlsError> {
    const OUTER_TYPE: u8 = 0;
    const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;

    // Drawn per connection, exactly where uTLS draws them: the cipher suite and
    // the payload length are picked when the extension is built, so a profile
    // that offers two AEADs must not send the same one every time.
    let aead_id = draw_candidate(grease.aead_ids, "encrypted_client_hello AEAD")?;
    let length = draw_candidate(grease.lengths, "encrypted_client_hello length")?;
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
) -> Result<Option<ClientHelloGreasePlan>, RustlsError> {
    let grease_value = profile
        .cipher_suites
        .iter()
        .chain(profile.key_shares.iter().map(|key_share| &key_share.group))
        .chain(
            profile
                .extensions
                .iter()
                .map(|extension| &extension.extension_type),
        )
        .copied()
        .find(|value| is_grease_value(*value));
    let Some(grease_value) = grease_value else {
        return Ok(None);
    };

    let mut grease = ClientHelloGreasePlan::new(grease_value)?;
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
    if let Some(position) = profile
        .key_shares
        .iter()
        .position(|key_share| is_grease_value(key_share.group))
    {
        grease = grease.with_key_share_position(position);
    }
    let mut non_grease_position = 0;
    for extension in profile.extensions {
        if is_grease_value(extension.extension_type) {
            grease = grease.with_extension(ClientHelloGreaseExtension::new(
                extension.extension_type,
                non_grease_position,
                vec![0; extension.payload_len],
            )?)?;
        } else {
            non_grease_position += 1;
        }
    }

    Ok(Some(grease))
}

fn signature_algorithms_payload(algorithms: &[u16]) -> Result<Vec<u8>, RustlsError> {
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

fn application_settings_payload(protocols: &[&[u8]]) -> Result<Vec<u8>, RustlsError> {
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

fn push_exact_or_raw_extension(
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

    /// The two ECH GREASE schemes the profile table records: Chrome's
    /// `BoringGREASEECH` (body 186, payload 144) and Firefox's
    /// (`CandidatePayloadLens: []uint16{223}`, body 281, payload 239).
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
}
