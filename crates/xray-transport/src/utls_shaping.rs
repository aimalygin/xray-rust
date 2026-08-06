//! Translates a uTLS ClientHello profile into a rustls `ClientHelloPlan`.
//!
//! `apply_utls_profile` sets everything the profile describes — cipher
//! suites, extensions, GREASE, padding — but deliberately leaves the hello
//! random, session id, and key share untouched; filling those in is the
//! caller's responsibility. That split is what lets REALITY's customizer
//! (which pins all three for its handshake patching) and the plain-TLS
//! customizer (which lets rustls generate them normally) share this same
//! plan-building logic.
//!
//! Callers that need to override part of the shaped plan may do so after
//! `apply_utls_profile` returns: `ClientHelloPlan` setters are last-write-wins
//! and the plan is only read once, at encode time. For example, a later
//! `.with_alpn_protocols(...)` call cleanly replaces the profile's own ALPN
//! list.

use rustls::{
    client::{
        ClientHelloAdvertisedCipherSuites, ClientHelloAdvertisedSupportedGroups,
        ClientHelloAdvertisedSupportedVersions, ClientHelloAlpnProtocols,
        ClientHelloCertificateCompressionAlgorithms, ClientHelloExactExtension,
        ClientHelloExactExtensions, ClientHelloExtensionOrder, ClientHelloExtensionPlan,
        ClientHelloForcedExtensions, ClientHelloGreaseExtension, ClientHelloGreasePlan,
        ClientHelloKeySharePlan, ClientHelloPaddingPlan, ClientHelloPlan, ClientHelloRawExtension,
        ClientHelloRawExtensions, ClientHelloRawKeyShare, ClientHelloRawKeyShares,
        ClientHelloSupportedGroups, ClientHelloSupportedVersions,
    },
    CertificateCompressionAlgorithm, CipherSuite, Error as RustlsError, NamedGroup,
    ProtocolVersion,
};

use crate::utls_profiles::UtlsClientHelloProfile;

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
const BROTLI_CERTIFICATE_COMPRESSION: u16 = 0x0002;
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
) -> Result<ClientHelloPlan, RustlsError> {
    plan = plan
        .with_advertised_cipher_suites(advertised_cipher_suites(profile)?)
        .with_supported_versions(supported_versions(profile)?);

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
    if profile_uses_structured_certificate_compression(profile) {
        plan = plan.with_certificate_compression_algorithms(certificate_compression(profile)?);
    }

    let forced_extensions = forced_extensions(profile);
    let extension_plan = extension_plan(profile, false)?;
    let (exact_extensions, raw_extensions) = extension_payloads(profile)?;

    plan = plan
        .with_forced_extensions(forced_extensions)
        .with_extensions(extension_plan);
    if !profile.supported_versions.is_empty() {
        plan = plan.with_extension_order(extension_order(profile, false)?);
    }

    if let Some(exact_extensions) = exact_extensions {
        plan = plan.with_exact_extensions(exact_extensions);
    }
    if let Some(raw_extensions) = raw_extensions {
        plan = plan.with_raw_extensions(raw_extensions);
    }
    if let Some(grease) = grease_plan(profile)? {
        plan = plan.with_grease(grease);
    }
    if profile.padding_length.is_some() {
        plan = plan.with_padding(ClientHelloPaddingPlan::pad_to_handshake_size(
            BORINGSSL_PADDING_TARGET_HANDSHAKE_SIZE,
        )?);
    }

    Ok(plan)
}

fn advertised_cipher_suites(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloAdvertisedCipherSuites, RustlsError> {
    ClientHelloAdvertisedCipherSuites::try_from(
        profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease_value(*suite))
            .map(CipherSuite::from)
            .collect::<Vec<_>>(),
    )
}

fn supported_versions(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloSupportedVersions, RustlsError> {
    let versions = if profile.supported_versions.contains(&TLS_VERSION_1_3) {
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
    _profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloCertificateCompressionAlgorithms, RustlsError> {
    ClientHelloCertificateCompressionAlgorithms::try_from(vec![
        CertificateCompressionAlgorithm::Brotli,
    ])
}

/// Replaces the profile's own ALPN list with a configured one.
///
/// A profile that carries no ALPN extension needs more than a new list: the
/// extension is suppressed by the profile's extension plan, and rustls rejects
/// an extension order that omits an emitted extension, so appending ALPN to
/// the hello means un-suppressing *and* ordering it in the same breath. Xray
/// appends it last (`tls.go`'s `if !hasALPNExtension`), so this does too.
pub(crate) fn apply_alpn_override(
    mut plan: ClientHelloPlan,
    profile: &'static UtlsClientHelloProfile,
    protocols: &[Vec<u8>],
) -> Result<ClientHelloPlan, RustlsError> {
    plan = plan.with_alpn_protocols(ClientHelloAlpnProtocols::try_from(protocols.to_vec())?);
    if profile_has_extension(profile, EXT_ALPN) {
        return Ok(plan);
    }

    plan = plan.with_extensions(extension_plan(profile, true)?);
    // No profile that lacks ALPN pins an extension order today, but the two
    // must move together: enabling the extension without ordering it is an
    // error inside rustls, not a shape difference.
    if !profile.supported_versions.is_empty() {
        plan = plan.with_extension_order(extension_order(profile, true)?);
    }

    Ok(plan)
}

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
                || !profile_uses_structured_certificate_compression(profile)
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
    if !profile_uses_structured_certificate_compression(profile)
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
    if let Some(length) = profile.encrypted_client_hello_length {
        exact_extensions.push(ClientHelloExactExtension::new(
            EXT_ENCRYPTED_CLIENT_HELLO,
            encrypted_client_hello_payload(length)?,
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

fn encrypted_client_hello_payload(length: usize) -> Result<Vec<u8>, RustlsError> {
    // The finalizer path reparses ClientHello, so the ECH GREASE placeholder
    // must be syntactically valid even though it remains opaque filler.
    const OUTER_TYPE: u8 = 0;
    const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
    const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
    const CONFIG_ID: u8 = 0;
    const MIN_OUTER_LEN: usize = 11;

    if length < MIN_OUTER_LEN {
        return Err(RustlsError::General(
            "encrypted_client_hello payload is too short".into(),
        ));
    }

    let encrypted_payload_len = length - 10;
    let encrypted_payload_len = u16::try_from(encrypted_payload_len).map_err(|_| {
        RustlsError::General("encrypted_client_hello payload cannot exceed 65535 bytes".into())
    })?;
    let mut payload = Vec::with_capacity(length);
    payload.push(OUTER_TYPE);
    payload.extend_from_slice(&HPKE_KDF_HKDF_SHA256.to_be_bytes());
    payload.extend_from_slice(&HPKE_AEAD_AES_128_GCM.to_be_bytes());
    payload.push(CONFIG_ID);
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&encrypted_payload_len.to_be_bytes());
    payload.resize(length, 0);
    Ok(payload)
}

fn grease_plan(
    profile: &UtlsClientHelloProfile,
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
    if let Some(position) = profile
        .cipher_suites
        .iter()
        .position(|suite| is_grease_value(*suite))
    {
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
        && profile_uses_structured_certificate_compression(profile)
}

fn profile_has_extension(profile: &UtlsClientHelloProfile, extension_type: u16) -> bool {
    profile
        .extensions
        .iter()
        .any(|extension| extension.extension_type == extension_type)
}

pub(crate) fn profile_uses_structured_certificate_compression(
    profile: &UtlsClientHelloProfile,
) -> bool {
    profile.certificate_compression_algorithms == [BROTLI_CERTIFICATE_COMPRESSION]
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
        _ => None,
    }
}

fn is_grease_value(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}
