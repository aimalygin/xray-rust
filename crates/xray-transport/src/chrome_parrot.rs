//! Xray-core's ChromeParrot: the default shape of its QUIC client handshake.
//!
//! Xray-core v26.10.31 dials Hysteria, XHTTP over HTTP/3 and XDRIVE's HTTP/3
//! client over the apernet quic-go fork with `quic.Config.ChromeParrot` on,
//! unless `finalmask.quicParams.disableChromeParrot` is true. The fork then
//! shapes the client's handshake like Google Chrome's. What it does below TLS
//! is the vendored quinn-proto's `TransportConfig::chrome_parrot`. This module
//! holds the rest:
//!
//! - the values quic-go's `populateConfig` pins along with it, which
//!   [`crate::stream::H3QuicConfig`] applies when its `chrome_parrot` is set;
//! - [`ChromeQuicHello`], the TLS ClientHello: uTLS's Chrome QUIC spec
//!   (`internal/handshake/chrome_client_hello.go`), not one of uTLS's TCP
//!   presets, with its extensions in a new random order on every connection.

use std::time::Duration;

use rand::{rngs::OsRng, RngCore};
use rustls::client::{
    ClientHelloAdvertisedSupportedGroups, ClientHelloAdvertisedSupportedVersions,
    ClientHelloCertificateCompressionAlgorithms, ClientHelloCipherSuites, ClientHelloContext,
    ClientHelloCustomizer, ClientHelloExactExtension, ClientHelloExactExtensions,
    ClientHelloExtensionOrder, ClientHelloExtensionPlan, ClientHelloKeySharePlan,
    ClientHelloPlan, ClientHelloRawExtensions, ClientHelloSupportedGroups,
    ClientHelloSupportedVersions,
};
use rustls::{CertificateCompressionAlgorithm, CipherSuite, Error as RustlsError, NamedGroup};

use crate::sudoku::gorand::GoRand;
use crate::utls_profiles::{UtlsEchGrease, HPKE_AEAD_AES_128_GCM};
use crate::utls_shaping::{
    application_settings_payload, encrypted_client_hello_payload, push_exact_or_raw_extension,
    signature_algorithms_payload,
};

/// quic-go's `chromeMaxIdleTimeout`
pub(crate) const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// `chromeInitialMaxStreamData`, every stream's starting window
pub(crate) const INITIAL_STREAM_RECEIVE_WINDOW: u64 = 6_291_456;
/// `chromeInitialMaxData`, the connection's starting window
pub(crate) const INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 15_728_640;
/// `chromeMaxIncomingStreams`
pub(crate) const MAX_INCOMING_STREAMS: u64 = 100;
/// `chromeMaxIncomingUniStreams`
pub(crate) const MAX_INCOMING_UNI_STREAMS: u64 = 103;
/// `chromeInitialPacketSize`, the size of every Initial datagram
pub(crate) const INITIAL_PACKET_SIZE: u16 = 1250;
/// `ChromeConnectionIDLenInitial`, the first destination connection ID's
/// length; quic-go otherwise draws one between 8 and 20
pub(crate) const INITIAL_CONNECTION_ID_LEN: usize = 8;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_CERTIFICATE_COMPRESSION: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// ALPS at the newer codepoint, which uTLS's presets do not use
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The spec's extensions in its own order, before the shuffle
const EXTENSIONS: [u16; 11] = [
    EXT_SERVER_NAME,
    EXT_SUPPORTED_GROUPS,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_ALPN,
    EXT_CERTIFICATE_COMPRESSION,
    EXT_SUPPORTED_VERSIONS,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_KEY_SHARE,
    EXT_QUIC_TRANSPORT_PARAMETERS,
    EXT_APPLICATION_SETTINGS,
    EXT_ENCRYPTED_CLIENT_HELLO,
];

/// What rustls would add on its own and the spec does not carry
const DISABLED_EXTENSIONS: [u16; 5] = [
    EXT_STATUS_REQUEST,
    EXT_EC_POINT_FORMATS,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_SESSION_TICKET,
    EXT_RENEGOTIATION_INFO,
];

/// The spec's signature algorithms, in its order
const SIGNATURE_ALGORITHMS: [u16; 9] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
    0x0201, // rsa_pkcs1_sha1
];

/// `BoringGREASEECH`: one cipher suite and a payload of 128, 160, 192 or 224
/// bytes plus the AEAD tag, drawn per connection; these are the resulting
/// extension body lengths.
const ECH_GREASE: UtlsEchGrease = UtlsEchGrease {
    aead_ids: &[HPKE_AEAD_AES_128_GCM],
    lengths: &[186, 218, 250, 282],
};

/// The ClientHello quic-go's ChromeParrot sends through uTLS.
///
/// No GREASE value anywhere; TLS 1.3 alone; suites AES-128-GCM, AES-256-GCM
/// and ChaCha20-Poly1305; groups X25519MLKEM768, X25519, P-256 and P-384 with
/// key shares for the first two; Chrome's nine signature algorithms; brotli
/// certificate compression; `psk_dhe_ke`; ALPS and ALPN for the configured
/// protocols; and a GREASE ECH extension. uTLS shuffles the extensions with
/// Go's `math/rand` seeded from `crypto/rand`, every connection anew.
///
/// The configuration it is installed on supplies what the spec takes from
/// Go's: the ALPN list and the server name. Session resumption and 0-RTT stay
/// off, as the fork turns them off.
#[derive(Debug, Default)]
pub(crate) struct ChromeQuicHello {
    #[cfg(test)]
    draws: Option<HelloDraws>,
}

/// The per-connection draws a test hands in instead of the system's
#[cfg(test)]
#[derive(Debug, Clone)]
struct HelloDraws {
    shuffle_seed: [u8; 8],
    random: [u8; 32],
    encrypted_client_hello: Vec<u8>,
}

/// `crypto/rand.Int(crypto/rand.Reader, math.MaxInt64)`: eight bytes with the
/// top bit cleared, read again in the one case the value is not below the
/// bound
fn int63(bytes: [u8; 8]) -> Option<i64> {
    let mut bytes = bytes;
    bytes[0] &= 0x7f;
    let value = i64::from_be_bytes(bytes);
    (value < i64::MAX).then_some(value)
}

/// `ShuffleChromeTLSExtensions` for a spec without GREASE, padding or
/// pre-shared key extensions: a plain shuffle with
/// `rand.New(rand.NewSource(seed))`
fn shuffled_extensions(seed: i64) -> [u16; 11] {
    let mut order = EXTENSIONS;
    GoRand::new(seed).shuffle(&mut order);
    order
}

impl ChromeQuicHello {
    fn shuffle_seed(&self) -> Result<i64, RustlsError> {
        #[cfg(test)]
        if let Some(draws) = &self.draws {
            return int63(draws.shuffle_seed)
                .ok_or_else(|| RustlsError::General("a seed uTLS would redraw".into()));
        }
        loop {
            let mut bytes = [0; 8];
            OsRng.try_fill_bytes(&mut bytes).map_err(|error| {
                RustlsError::General(format!("the extension order needs randomness: {error}"))
            })?;
            if let Some(seed) = int63(bytes) {
                return Ok(seed);
            }
        }
    }

    fn encrypted_client_hello(&self) -> Result<Vec<u8>, RustlsError> {
        #[cfg(test)]
        if let Some(draws) = &self.draws {
            return Ok(draws.encrypted_client_hello.clone());
        }
        encrypted_client_hello_payload(&ECH_GREASE)
    }
}

impl ClientHelloCustomizer for ChromeQuicHello {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        if !context.is_quic {
            return Err(RustlsError::General(
                "the ChromeParrot ClientHello is a QUIC one".into(),
            ));
        }
        let mut alpn: Vec<&[u8]> = context
            .alpn_protocols
            .iter()
            .map(|protocol| protocol.as_slice())
            .collect();
        // The spec falls back to h3 when the configuration names nothing.
        if alpn.is_empty() {
            alpn.push(b"h3");
        }

        let groups = vec![
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ];
        let mut exact = vec![
            ClientHelloExactExtension::new(
                EXT_SIGNATURE_ALGORITHMS,
                signature_algorithms_payload(&SIGNATURE_ALGORITHMS)?,
            )?,
            ClientHelloExactExtension::new(
                EXT_ENCRYPTED_CLIENT_HELLO,
                self.encrypted_client_hello()?,
            )?,
        ];
        let mut raw = Vec::new();
        push_exact_or_raw_extension(
            &mut exact,
            &mut raw,
            EXT_APPLICATION_SETTINGS,
            application_settings_payload(&alpn)?,
        )?;

        let mut plan = ClientHelloPlan::new()
            .with_cipher_suites(ClientHelloCipherSuites::try_from(vec![
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ])?)
            .with_supported_versions(ClientHelloSupportedVersions::try_from(vec![
                rustls::ProtocolVersion::TLSv1_3,
            ])?)
            .with_advertised_supported_versions(ClientHelloAdvertisedSupportedVersions::try_from(
                vec![rustls::ProtocolVersion::TLSv1_3],
            )?)
            .with_supported_groups(ClientHelloSupportedGroups::try_from(groups.clone())?)
            .with_advertised_supported_groups(ClientHelloAdvertisedSupportedGroups::try_from(
                groups,
            )?)
            .with_key_share_plan(ClientHelloKeySharePlan::try_from(vec![
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
            ])?)
            .with_certificate_compression_algorithms(
                ClientHelloCertificateCompressionAlgorithms::try_from(vec![
                    CertificateCompressionAlgorithm::Brotli,
                ])?,
            )
            .with_extensions(ClientHelloExtensionPlan::try_from(
                DISABLED_EXTENSIONS.to_vec(),
            )?)
            .with_extension_order(ClientHelloExtensionOrder::try_from(
                shuffled_extensions(self.shuffle_seed()?).to_vec(),
            )?)
            .with_exact_extensions(ClientHelloExactExtensions::try_from(exact)?);
        if !raw.is_empty() {
            plan = plan.with_raw_extensions(ClientHelloRawExtensions::try_from(raw)?);
        }
        #[cfg(test)]
        if let Some(draws) = &self.draws {
            plan = plan.with_random(draws.random);
        }
        Ok(Some(plan))
    }
}

/// Keeps only what the ChromeParrot ClientHello offers: brotli.
pub(crate) fn retain_brotli(
    decompressors: &mut Vec<&'static dyn rustls::compress::CertDecompressor>,
) {
    decompressors
        .retain(|decompressor| decompressor.algorithm() == CertificateCompressionAlgorithm::Brotli);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use serde_json::Value;

    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture() -> Value {
        let path = std::env::var("XRAY_CHROME_PARROT_INITIALS").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/chrome-parrot/initials.json"
            )
            .to_owned()
        });
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn extension(case: &Value, extension_type: u16) -> Vec<u8> {
        case["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["type"] == extension_type)
            .map(|e| unhex(e["data"].as_str().unwrap()))
            .unwrap()
    }

    /// Zeroes the key share's key material, which no two implementations
    /// generate alike, keeping its groups and lengths.
    fn mask_key_shares(hello: &mut [u8]) {
        let mut p = 4 + 2 + 32;
        p += 1 + usize::from(hello[p]);
        p += 2 + usize::from(u16::from_be_bytes([hello[p], hello[p + 1]]));
        p += 1 + usize::from(hello[p]);
        let end = p + 2 + usize::from(u16::from_be_bytes([hello[p], hello[p + 1]]));
        p += 2;
        while p < end {
            let typ = u16::from_be_bytes([hello[p], hello[p + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[p + 2], hello[p + 3]]));
            if typ == EXT_KEY_SHARE {
                let mut q = p + 4 + 2;
                while q < p + 4 + len {
                    let key_len = usize::from(u16::from_be_bytes([hello[q + 2], hello[q + 3]]));
                    hello[q + 4..q + 4 + key_len].fill(0);
                    q += 4 + key_len;
                }
            }
            p += 4 + len;
        }
    }

    fn client_hello(hello: ChromeQuicHello, transport_parameters: Vec<u8>) -> Vec<u8> {
        let config = crate::tls::chrome_quic_rustls_config(true, &[], &[], b"h3", hello).unwrap();
        let mut connection = rustls::quic::ClientConnection::new(
            Arc::new(config),
            rustls::quic::Version::V1,
            ServerName::try_from("chrome-parrot.example").unwrap(),
            transport_parameters,
        )
        .unwrap();
        let mut out = Vec::new();
        connection.write_hs(&mut out);
        out
    }

    /// Given uTLS's draws, the ClientHello is Xray's own, byte for byte, but
    /// for the key material in the key shares.
    #[test]
    fn client_hello_matches_xray() {
        let fixture = fixture();
        for case in fixture["cases"].as_array().unwrap() {
            let shuffle_seed = case["random_reads"]
                .as_array()
                .unwrap()
                .iter()
                .find(|read| {
                    read["source"]
                        .as_str()
                        .unwrap()
                        .ends_with("utls.ShuffleChromeTLSExtensions")
                })
                .map(|read| unhex(read["hex"].as_str().unwrap()))
                .unwrap();
            let hello = ChromeQuicHello {
                draws: Some(HelloDraws {
                    shuffle_seed: shuffle_seed.try_into().unwrap(),
                    random: unhex(case["client_hello_random"].as_str().unwrap())
                        .try_into()
                        .unwrap(),
                    encrypted_client_hello: extension(case, EXT_ENCRYPTED_CLIENT_HELLO),
                }),
            };
            let mut ours = client_hello(hello, extension(case, EXT_QUIC_TRANSPORT_PARAMETERS));
            let mut theirs = unhex(case["client_hello"].as_str().unwrap());
            mask_key_shares(&mut ours);
            mask_key_shares(&mut theirs);
            assert_eq!(hex(&ours), hex(&theirs), "seed {}", case["seed"]);
        }
    }

    /// Every connection draws its own order, and over many connections every
    /// extension takes every place.
    #[test]
    fn the_extension_order_is_drawn_per_connection() {
        let mut seen = [[false; 11]; 11];
        let mut orders = std::collections::HashSet::new();
        for _ in 0..400 {
            let order = shuffled_extensions(ChromeQuicHello::default().shuffle_seed().unwrap());
            for (place, extension) in order.iter().enumerate() {
                let index = EXTENSIONS.iter().position(|e| e == extension).unwrap();
                seen[index][place] = true;
            }
            orders.insert(order);
        }
        assert!(seen.iter().flatten().all(|seen| *seen));
        assert!(orders.len() > 390);
    }

    #[test]
    fn int63_is_go_crypto_rand_int() {
        assert_eq!(int63([0xff; 8]), None);
        assert_eq!(
            int63([0xe2, 0xe2, 0x30, 0xe1, 0xee, 0x63, 0x5a, 0xcc]),
            Some(0x62e2_30e1_ee63_5acc)
        );
    }
}
