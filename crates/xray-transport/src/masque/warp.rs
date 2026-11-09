//! Cloudflare WARP's MASQUE flavour, as Xray-core v26.10.31's `warp.go`
//! sets it up: the device authenticates with a certificate made for its
//! key at each dial, and the endpoint is known by its key.
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivateSec1KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::SignatureScheme;
use zeroize::Zeroizing;

use super::IpPrefix;
use crate::{TransportError, WarpTls};

/// What `masqueSettings.warp` gives a dial.
#[derive(Clone)]
pub struct MasqueWarp {
    /// The device key's P-256 private scalar.
    pub private_key: Zeroizing<Vec<u8>>,
    /// The endpoint's SubjectPublicKeyInfo.
    pub public_key: Vec<u8>,
    /// The tunnel's addresses, which the proxy assigns no others.
    pub addresses: Vec<IpPrefix>,
}

impl fmt::Debug for MasqueWarp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueWarp")
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}

impl MasqueWarp {
    /// Xray's `useWarp` for one dial: a fresh certificate for the device
    /// key, and the endpoint's key to check.
    pub fn tls(&self) -> Result<WarpTls, TransportError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs() as i64);
        let (certificate, key) = certificate(&self.private_key, now)?;
        Ok(WarpTls::new(
            Arc::new(CertifiedKey::new(vec![certificate], key)),
            self.public_key.clone(),
        ))
    }
}

fn key_error(error: impl fmt::Display) -> TransportError {
    TransportError::TlsConfig(format!("invalid WARP private key: {error}"))
}

/// Xray's `warpCertificate`: a self-signed certificate for the key, as
/// Go's `x509.CreateCertificate` writes it for a template with only a
/// random 128-bit serial and a validity from an hour before `now` to a day
/// after: version 3, empty names, no extensions, ECDSA with SHA-256.
pub(crate) fn certificate(
    scalar: &[u8],
    now: i64,
) -> Result<(CertificateDer<'static>, Arc<dyn SigningKey>), TransportError> {
    // SEC 1 without the public key, which the provider derives.
    let mut sec1 = der(0x02, &[1]);
    sec1.extend(der(0x04, scalar));
    sec1.extend(der(0xa0, &der(0x06, OID_P256)));
    let sec1 = Zeroizing::new(der(0x30, &sec1));
    let key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Sec1(
        PrivateSec1KeyDer::from(sec1.to_vec()),
    ))
    .map_err(key_error)?;
    let spki = key
        .public_key()
        .ok_or_else(|| key_error("no public key"))?
        .to_vec();
    let mut serial = [0u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut serial)
        .map_err(|_| key_error("no randomness for a serial"))?;
    let tbs = tbs_certificate(&serial, now, &spki);
    let signature = key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .ok_or_else(|| key_error("not a P-256 key"))?
        .sign(&tbs)
        .map_err(key_error)?;
    let mut certificate = tbs;
    certificate.extend(ecdsa_with_sha256());
    certificate.extend(bit_string(&signature));
    Ok((CertificateDer::from(der(0x30, &certificate)), key))
}

const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

fn tbs_certificate(serial: &[u8; 16], now: i64, spki: &[u8]) -> Vec<u8> {
    let mut tbs = der(0xa0, &der(0x02, &[2]));
    tbs.extend(der(0x02, &positive_integer(serial)));
    tbs.extend(ecdsa_with_sha256());
    tbs.extend(der(0x30, &[]));
    let mut validity = utc_time(now - 3600);
    validity.extend(utc_time(now + 24 * 3600));
    tbs.extend(der(0x30, &validity));
    tbs.extend(der(0x30, &[]));
    tbs.extend_from_slice(spki);
    der(0x30, &tbs)
}

fn ecdsa_with_sha256() -> Vec<u8> {
    der(0x30, &der(0x06, OID_ECDSA_SHA256))
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    der(0x03, &content)
}

/// A non-negative big-endian number as a DER INTEGER's content.
fn positive_integer(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let mut content = bytes[start..].to_vec();
    if content.first().is_none_or(|&b| b & 0x80 != 0) {
        content.insert(0, 0);
    }
    content
}

/// Go's UTCTime: `YYMMDDHHMMSSZ`, for the years 1950 to 2049.
fn utc_time(unix: i64) -> Vec<u8> {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let text = format!(
        "{:02}{month:02}{day:02}{:02}{:02}{:02}Z",
        year.rem_euclid(100),
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    );
    der(0x17, text.as_bytes())
}

/// The proleptic Gregorian date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// One DER element.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut element = vec![tag];
    let len = content.len();
    if len < 0x80 {
        element.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        element.push(0x80 | (bytes.len() - start) as u8);
        element.extend_from_slice(&bytes[start..]);
    }
    element.extend_from_slice(content);
    element
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[test]
    fn the_certificate_is_gos_for_the_key() {
        let scalar = [0x11u8; 32];
        // 2026-11-08T12:00:00Z
        let now = 1_794_225_600;
        let (cert, key) = certificate(&scalar, now).unwrap();
        let (rest, parsed) = X509Certificate::from_der(cert.as_ref()).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.version().0, 2);
        assert!(parsed.subject().as_raw().len() == 2 && parsed.issuer().as_raw().len() == 2);
        assert!(parsed.extensions().is_empty());
        assert_eq!(parsed.validity().not_before.timestamp(), now - 3600);
        assert_eq!(parsed.validity().not_after.timestamp(), now + 86_400);
        assert_eq!(
            parsed.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.10045.4.3.2"
        );
        assert_eq!(parsed.public_key().raw, key.public_key().unwrap().as_ref());
        // Signed by the key itself, over the to-be-signed part.
        let verifier = rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(scheme, _)| *scheme == SignatureScheme::ECDSA_NISTP256_SHA256)
            .unwrap()
            .1[0];
        let point = &parsed.public_key().subject_public_key.data;
        let message = parsed.tbs_certificate.as_ref();
        assert!(verifier
            .verify_signature(point, message, &parsed.signature_value.data)
            .is_ok());
        // Each dial draws another serial.
        let (again, _) = certificate(&scalar, now).unwrap();
        assert_ne!(cert, again);
    }

    #[test]
    fn utc_times_and_serials_are_minimal_der() {
        assert_eq!(utc_time(0), der(0x17, b"700101000000Z"));
        assert_eq!(utc_time(951_782_400), der(0x17, b"000229000000Z"));
        assert_eq!(positive_integer(&[0, 0, 0x7f]), [0x7f]);
        assert_eq!(positive_integer(&[0x80]), [0, 0x80]);
        assert_eq!(positive_integer(&[0, 0]), [0]);
        assert_eq!(der(0x04, &[0; 200])[..3], [0x04, 0x81, 200]);
    }
}
