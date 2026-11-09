//! `masqueSettings.warp` as Xray-core v26.10.31's `infra/conf` reads it:
//! `parseWarpPrivateKey`, `parseWarpPublicKey` and `parseWarpAddress`, down
//! to the rules of Go's `encoding/pem`, `encoding/base64`, `encoding/asn1`,
//! `crypto/x509` and `net/netip` they rest on.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use num_bigint::{BigInt, BigUint, Sign};
use zeroize::Zeroizing;

/// The device key's P-256 private scalar, as Xray-core keeps it: from a
/// PKCS #8 or SEC 1 key in PEM or base64.
pub(super) fn private_key(text: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let der = Zeroizing::new(decode(text)?);
    // Go tries PKCS #8, then SEC 1 when the PKCS #8 structure does not
    // parse at all; a PKCS #8 key of another kind is refused.
    let key = match pkcs8(&der) {
        Ok(Some((params, inner))) => ec_private_key(params, inner),
        Ok(None) => return Err("not an ECDSA P-256 key".to_owned()),
        Err(()) => ec_private_key(None, &der)
            .map_err(|_| "neither a PKCS #8 nor a SEC 1 private key".to_owned()),
    }?;
    match key {
        (Curve::P256, scalar) => Ok(scalar),
        _ => Err("not an ECDSA P-256 key".to_owned()),
    }
}

/// The endpoint's public key, a SubjectPublicKeyInfo that Go's
/// `x509.ParsePKIXPublicKey` takes, kept as given.
pub(super) fn public_key(text: &str) -> Result<Vec<u8>, String> {
    let der = decode(text)?;
    if pkix_public_key(&der) {
        Ok(der)
    } else {
        Err("not a PKIX public key".to_owned())
    }
}

/// Xray's `parseWarpAddress`: prefixes or addresses, at most one of each
/// family, as Go's `netip` reads and writes them.
pub(super) fn addresses(list: &[String]) -> Result<Vec<(IpAddr, u8)>, String> {
    if list.is_empty() {
        return Err(r#""address" in "warp" is not set"#.to_owned());
    }
    let (mut v4, mut v6) = (false, false);
    let mut addresses = Vec::with_capacity(list.len());
    for text in list {
        let (addr, len) = match parse_prefix(text) {
            Some(prefix) => prefix,
            None => match parse_addr(text) {
                Some(addr) => (addr, if addr.is_ipv4() { 32 } else { 128 }),
                None => return Err(format!(r#"invalid "address" in "warp": {text}"#)),
            },
        };
        if addr.is_ipv4() && v4 || addr.is_ipv6() && v6 {
            return Err(
                r#""address" in "warp" takes at most one IPv4 and one IPv6 address"#.to_owned(),
            );
        }
        v4 |= addr.is_ipv4();
        v6 |= addr.is_ipv6();
        addresses.push((addr, len));
    }
    Ok(addresses)
}

// ---- Text ------------------------------------------------------------------

/// Xray's `decodeWarpKey`: trimmed, then the first PEM block's bytes, else
/// standard base64.
fn decode(text: &str) -> Result<Vec<u8>, String> {
    // strings.TrimSpace trims Unicode White_Space, as `str::trim` does.
    let text = text.trim();
    if text.is_empty() {
        return Err("empty key".to_owned());
    }
    if let Some(bytes) = pem_decode(text.as_bytes()) {
        return Ok(bytes);
    }
    std_base64(text.as_bytes()).ok_or_else(|| "neither PEM nor base64".to_owned())
}

/// Go's `base64.StdEncoding`: padding required, `\r` and `\n` skipped, the
/// unused bits of the last symbol ignored.
fn std_base64(text: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    use base64::Engine as _;
    const GO_STD: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    let stripped: Vec<u8> = text
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    GO_STD.decode(stripped).ok()
}

/// Go's `pem.Decode`: the bytes of the first block that decodes, wherever
/// it starts.
fn pem_decode(data: &[u8]) -> Option<Vec<u8>> {
    const START: &[u8] = b"\n-----BEGIN ";
    const END: &[u8] = b"\n-----END ";
    const END_OF_LINE: &[u8] = b"-----";
    let mut rest = data;
    loop {
        if rest.starts_with(&START[1..]) {
            rest = &rest[START.len() - 1..];
        } else if let Some(i) = find(rest, START) {
            rest = &rest[i + START.len()..];
        } else {
            return None;
        }
        let (type_line, after) = get_line(rest);
        rest = after;
        let Some(kind) = type_line.strip_suffix(END_OF_LINE) else {
            continue;
        };
        let mut headers = false;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next) = get_line(rest);
            if !line.contains(&b':') {
                break;
            }
            headers = true;
            rest = next;
        }
        let (end, trailer) = if !headers && rest.starts_with(&END[1..]) {
            (0, END.len() - 1)
        } else {
            match find(rest, END) {
                Some(i) => (i, i + END.len()),
                None => continue,
            }
        };
        let trailer = &rest[trailer..];
        let trailer_len = kind.len() + END_OF_LINE.len();
        if trailer.len() < trailer_len {
            continue;
        }
        let (trailer, rest_of_line) = trailer.split_at(trailer_len);
        if !trailer.starts_with(kind) || !trailer.ends_with(END_OF_LINE) {
            continue;
        }
        if !get_line(rest_of_line).0.is_empty() {
            continue;
        }
        let body: Vec<u8> = rest[..end]
            .iter()
            .copied()
            .filter(|&b| b != b' ' && b != b'\t')
            .collect();
        match std_base64(&body) {
            Some(bytes) => return Some(bytes),
            None => continue,
        }
    }
}

/// Go's `getLine`: a line without its end and trailing spaces and tabs.
fn get_line(data: &[u8]) -> (&[u8], &[u8]) {
    let (mut line, rest) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &data[data.len()..]),
    };
    if data.len() > line.len() && line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    while let [head @ .., b' ' | b'\t'] = line {
        line = head;
    }
    (line, rest)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---- encoding/asn1 -----------------------------------------------------------

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_CONTEXT: u8 = 2;
const TAG_INTEGER: u32 = 2;
const TAG_BIT_STRING: u32 = 3;
const TAG_OCTET_STRING: u32 = 4;
const TAG_OID: u32 = 6;
const TAG_SEQUENCE: u32 = 16;

/// An element's header as `encoding/asn1` reads it.
#[derive(Clone, Copy)]
struct Header {
    class: u8,
    compound: bool,
    tag: u32,
    length: usize,
}

/// `parseTagAndLength`: the header at `offset` and the offset after it.
fn header(bytes: &[u8], offset: usize) -> Result<(Header, usize), ()> {
    let mut offset = offset;
    let b = *bytes.get(offset).ok_or(())?;
    offset += 1;
    let mut header = Header {
        class: b >> 6,
        compound: b & 0x20 != 0,
        tag: u32::from(b & 0x1f),
        length: 0,
    };
    if header.tag == 0x1f {
        let (tag, next) = base128(bytes, offset)?;
        if tag < 0x1f {
            return Err(());
        }
        header.tag = tag;
        offset = next;
    }
    let b = *bytes.get(offset).ok_or(())?;
    offset += 1;
    if b & 0x80 == 0 {
        header.length = usize::from(b & 0x7f);
    } else {
        let count = b & 0x7f;
        if count == 0 {
            return Err(());
        }
        for _ in 0..count {
            let b = *bytes.get(offset).ok_or(())?;
            offset += 1;
            if header.length >= 1 << 23 {
                return Err(());
            }
            header.length = header.length << 8 | usize::from(b);
            if header.length == 0 {
                return Err(());
            }
        }
        if header.length < 0x80 {
            return Err(());
        }
    }
    Ok((header, offset))
}

/// `parseBase128Int`.
fn base128(bytes: &[u8], offset: usize) -> Result<(u32, usize), ()> {
    let mut value: u64 = 0;
    for (shifted, &b) in bytes.get(offset..).ok_or(())?.iter().enumerate() {
        if shifted == 5 || shifted == 0 && b == 0x80 {
            return Err(());
        }
        value = value << 7 | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return u32::try_from(value)
                .ok()
                .filter(|&v| v <= i32::MAX as u32)
                .map(|v| (v, offset + shifted + 1))
                .ok_or(());
        }
    }
    Err(())
}

/// One field of a Go struct, as `parseField` reads it.
enum Field<'a> {
    Present(&'a [u8]),
    Absent,
}

/// A universal field of `tag` at `offset`; an optional one that is missing
/// or of another type leaves the offset where it was.
fn field<'a>(
    bytes: &'a [u8],
    offset: usize,
    tag: u32,
    compound: bool,
    optional: bool,
) -> Result<(Field<'a>, usize), ()> {
    if offset == bytes.len() {
        return if optional {
            Ok((Field::Absent, offset))
        } else {
            Err(())
        };
    }
    let (h, start) = header(bytes, offset)?;
    if h.class != CLASS_UNIVERSAL || h.tag != tag || h.compound != compound {
        return if optional {
            Ok((Field::Absent, offset))
        } else {
            Err(())
        };
    }
    let end = start
        .checked_add(h.length)
        .filter(|&e| e <= bytes.len())
        .ok_or(())?;
    Ok((Field::Present(&bytes[start..end]), end))
}

/// An optional field of `tag` wrapped in an explicit context tag `[n]`.
/// Go reads the inner element from the same buffer, whatever the wrapper's
/// length says.
fn explicit_field(bytes: &[u8], offset: usize, n: u32, tag: u32) -> Result<(Field<'_>, usize), ()> {
    if offset == bytes.len() {
        return Ok((Field::Absent, offset));
    }
    let (wrapper, start) = header(bytes, offset)?;
    if start == bytes.len() {
        return Err(());
    }
    if wrapper.class != CLASS_CONTEXT
        || wrapper.tag != n
        || !(wrapper.length == 0 || wrapper.compound)
    {
        return Ok((Field::Absent, offset));
    }
    if wrapper.length == 0 {
        return Err(());
    }
    let (h, inner) = header(bytes, start)?;
    if h.class != CLASS_UNIVERSAL || h.tag != tag || h.compound {
        return Ok((Field::Absent, offset));
    }
    let end = inner
        .checked_add(h.length)
        .filter(|&e| e <= bytes.len())
        .ok_or(())?;
    Ok((Field::Present(&bytes[inner..end]), end))
}

/// The contents of a SEQUENCE at the front of `bytes`, and what follows.
fn sequence(bytes: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    match field(bytes, 0, TAG_SEQUENCE, true, false)? {
        (Field::Present(contents), end) => Ok((contents, &bytes[end..])),
        (Field::Absent, _) => Err(()),
    }
}

/// `checkInteger` and `parseInt64`.
fn int64(bytes: &[u8]) -> Result<i64, ()> {
    check_integer(bytes)?;
    if bytes.len() > 8 {
        return Err(());
    }
    let mut value: i64 = 0;
    for &b in bytes {
        value = value << 8 | i64::from(b);
    }
    let shift = 64 - 8 * bytes.len() as u32;
    Ok(if shift == 64 {
        value
    } else {
        value << shift >> shift
    })
}

fn check_integer(bytes: &[u8]) -> Result<(), ()> {
    match bytes {
        [] => Err(()),
        [0, next, ..] if next & 0x80 == 0 => Err(()),
        [0xff, next, ..] if next & 0x80 != 0 => Err(()),
        _ => Ok(()),
    }
}

/// `parseObjectIdentifier`, as its components.
fn oid(bytes: &[u8]) -> Result<Vec<u32>, ()> {
    if bytes.is_empty() {
        return Err(());
    }
    let (first, mut offset) = base128(bytes, 0)?;
    let mut components = if first < 80 {
        vec![first / 40, first % 40]
    } else {
        vec![2, first - 80]
    };
    while offset < bytes.len() {
        let (value, next) = base128(bytes, offset)?;
        components.push(value);
        offset = next;
    }
    Ok(components)
}

/// `parseBitString`: the bits, right-aligned as `BitString.RightAlign`
/// returns them.
fn bit_string(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let (&padding, data) = bytes.split_first().ok_or(())?;
    if padding > 7
        || data.is_empty() && padding > 0
        || data
            .last()
            .is_some_and(|&last| last & ((1u8 << padding) - 1) != 0)
    {
        return Err(());
    }
    if padding == 0 || data.is_empty() {
        return Ok(data.to_vec());
    }
    let shift = u32::from(padding);
    let mut aligned = vec![data[0] >> shift];
    for i in 1..data.len() {
        aligned.push(data[i - 1] << (8 - shift) | data[i] >> shift);
    }
    Ok(aligned)
}

/// `pkix.AlgorithmIdentifier`: the algorithm and its parameters' complete
/// element, if any.
fn algorithm(bytes: &[u8]) -> Result<(Vec<u32>, Option<&[u8]>), ()> {
    let (Field::Present(oid_bytes), offset) = field(bytes, 0, TAG_OID, false, false)? else {
        return Err(());
    };
    let algorithm = oid(oid_bytes)?;
    let params = if offset == bytes.len() {
        None
    } else {
        let (h, start) = header(bytes, offset)?;
        let end = start
            .checked_add(h.length)
            .filter(|&e| e <= bytes.len())
            .ok_or(())?;
        Some(&bytes[offset..end])
    };
    Ok((algorithm, params))
}

// ---- crypto/x509 -------------------------------------------------------------

const OID_EC: &[u32] = &[1, 2, 840, 10045, 2, 1];
const OID_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_DSA: &[u32] = &[1, 2, 840, 10040, 4, 1];
const OID_ED25519: &[u32] = &[1, 3, 101, 112];
const OID_X25519: &[u32] = &[1, 3, 101, 110];
const OID_MLDSA44: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
const OID_MLDSA65: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
const OID_MLDSA87: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Curve {
    P224,
    P256,
    P384,
    P521,
}

impl Curve {
    fn from_oid(oid: &[u32]) -> Option<Self> {
        match oid {
            [1, 3, 132, 0, 33] => Some(Self::P224),
            [1, 2, 840, 10045, 3, 1, 7] => Some(Self::P256),
            [1, 3, 132, 0, 34] => Some(Self::P384),
            [1, 3, 132, 0, 35] => Some(Self::P521),
            _ => None,
        }
    }

    /// The field prime, the coefficient b and the group order, in hex.
    fn params(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::P224 => (
                "ffffffffffffffffffffffffffffffff000000000000000000000001",
                "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
                "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
            ),
            Self::P256 => (
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            ),
            Self::P384 => (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            ),
            Self::P521 => (
                "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
                "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            ),
        }
    }

    /// The group order as a scalar of the curve's size.
    fn order(self) -> Vec<u8> {
        let order = hex_uint(self.params().2).to_bytes_be();
        let mut bytes = vec![0; self.size() - order.len()];
        bytes.extend(order);
        bytes
    }

    /// The bytes of a scalar or a coordinate.
    fn size(self) -> usize {
        match self {
            Self::P224 => 28,
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// `ecdsa.ParseUncompressedPublicKey`: an uncompressed point with
    /// reduced coordinates, on the curve.
    fn valid_point(self, data: &[u8]) -> bool {
        let size = self.size();
        if data.len() != 1 + 2 * size || data[0] != 4 {
            return false;
        }
        let (p, b, _) = self.params();
        let (p, b) = (hex_uint(p), hex_uint(b));
        let x = BigUint::from_bytes_be(&data[1..1 + size]);
        let y = BigUint::from_bytes_be(&data[1 + size..]);
        if x >= p || y >= p {
            return false;
        }
        // y² = x³ - 3x + b (mod p)
        let lhs = &y * &y % &p;
        let rhs = (&x * &x % &p * &x + &p * 3u32 - &x * 3u32 % &p + b) % &p;
        lhs == rhs
    }
}

fn hex_uint(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("curve constant")
}

/// Go's PKCS #8 structure: `None` for a key of another algorithm, the EC
/// key's curve parameters and SEC 1 bytes otherwise; `Err` when the
/// structure itself does not parse.
/// An EC key in PKCS #8: the curve its parameters name, and its SEC 1 bytes.
type Pkcs8Ec<'a> = (Option<Vec<u32>>, &'a [u8]);

fn pkcs8(der: &[u8]) -> Result<Option<Pkcs8Ec<'_>>, ()> {
    let (contents, _) = sequence(der)?;
    let (Field::Present(version), offset) = field(contents, 0, TAG_INTEGER, false, false)? else {
        return Err(());
    };
    int64(version)?;
    let (Field::Present(algo), offset) = field(contents, offset, TAG_SEQUENCE, true, false)? else {
        return Err(());
    };
    let (algorithm, params) = algorithm(algo)?;
    let (Field::Present(key), _) = field(contents, offset, TAG_OCTET_STRING, false, false)? else {
        return Err(());
    };
    if algorithm != OID_EC {
        return Ok(None);
    }
    // The parameters name the curve when they hold an object identifier.
    let curve = params.and_then(|params| match field(params, 0, TAG_OID, false, false) {
        Ok((Field::Present(bytes), _)) => oid(bytes).ok(),
        _ => None,
    });
    Ok(Some((curve, key)))
}

/// Go's `parseECPrivateKey`: the curve and the scalar, normalized to the
/// curve's size and checked as `ecdsa.ParseRawPrivateKey` checks it.
fn ec_private_key(
    curve_oid: Option<Vec<u32>>,
    der: &[u8],
) -> Result<(Curve, Zeroizing<Vec<u8>>), String> {
    let malformed = |_| "malformed EC private key".to_owned();
    let (contents, _) = sequence(der).map_err(malformed)?;
    let (Field::Present(version), offset) =
        field(contents, 0, TAG_INTEGER, false, false).map_err(malformed)?
    else {
        return Err("malformed EC private key".to_owned());
    };
    let version = int64(version).map_err(malformed)?;
    let (Field::Present(scalar), offset) =
        field(contents, offset, TAG_OCTET_STRING, false, false).map_err(malformed)?
    else {
        return Err("malformed EC private key".to_owned());
    };
    let (named, offset) = explicit_field(contents, offset, 0, TAG_OID).map_err(malformed)?;
    let named = match named {
        Field::Present(bytes) => oid(bytes).map_err(malformed)?,
        Field::Absent => Vec::new(),
    };
    if let (Field::Present(bits), _) =
        explicit_field(contents, offset, 1, TAG_BIT_STRING).map_err(malformed)?
    {
        bit_string(bits).map_err(malformed)?;
    }
    if version != 1 {
        return Err(format!("unknown EC private key version {version}"));
    }
    let curve = Curve::from_oid(curve_oid.as_deref().unwrap_or(&named))
        .ok_or_else(|| "unknown elliptic curve".to_owned())?;
    let size = curve.size();
    let mut scalar = scalar;
    while scalar.len() > size {
        if scalar[0] != 0 {
            return Err("invalid private key length".to_owned());
        }
        scalar = &scalar[1..];
    }
    let mut normalized = Zeroizing::new(vec![0; size]);
    normalized[size - scalar.len()..].copy_from_slice(scalar);
    // Same-length big-endian bytes compare as the numbers they hold.
    if normalized.iter().all(|&b| b == 0) || normalized.as_slice() >= curve.order().as_slice() {
        return Err("invalid private key".to_owned());
    }
    Ok((curve, normalized))
}

/// Go's `ParsePKIXPublicKey`.
fn pkix_public_key(der: &[u8]) -> bool {
    let Ok((contents, rest)) = sequence(der) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    let Ok((Field::Present(algo), offset)) = field(contents, 0, TAG_SEQUENCE, true, false) else {
        return false;
    };
    let Ok((algorithm, params)) = algorithm(algo) else {
        return false;
    };
    let Ok((Field::Present(bits), _)) = field(contents, offset, TAG_BIT_STRING, false, false)
    else {
        return false;
    };
    let Ok(data) = bit_string(bits) else {
        return false;
    };
    let params = params.unwrap_or_default();
    match algorithm.as_slice() {
        OID_RSA => {
            params == [5, 0]
                && cb_sequence(&data).is_some_and(|key| {
                    let Some((n, key)) = cb_integer(key) else {
                        return false;
                    };
                    let Some((e, _)) = cb_integer(key) else {
                        return false;
                    };
                    n.sign() == Sign::Plus && e.sign() == Sign::Plus && e.bits() < 64
                })
        }
        OID_EC => cb_oid(params)
            .and_then(|oid| Curve::from_oid(&oid))
            .is_some_and(|curve| curve.valid_point(&data)),
        OID_ED25519 => params.is_empty() && data.len() == 32,
        OID_X25519 => params.is_empty() && data.len() == 32,
        OID_MLDSA44 => params.is_empty() && data.len() == 1312,
        OID_MLDSA65 => params.is_empty() && data.len() == 1952,
        OID_MLDSA87 => params.is_empty() && data.len() == 2592,
        OID_DSA => {
            let Some((y, _)) = cb_integer(&data) else {
                return false;
            };
            let Some(params) = cb_sequence(params) else {
                return false;
            };
            let mut values = vec![y];
            let mut rest = params;
            for _ in 0..3 {
                let Some((value, next)) = cb_integer(rest) else {
                    return false;
                };
                values.push(value);
                rest = next;
            }
            values.iter().all(|value| value.sign() == Sign::Plus)
        }
        _ => false,
    }
}

// ---- cryptobyte ----------------------------------------------------------------

/// cryptobyte's `ReadASN1`: the contents of an element with exactly `tag`
/// and what follows it.
fn cb_element(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    if first & 0x1f == 0x1f || first != tag {
        return None;
    }
    let (&len_byte, rest) = rest.split_first()?;
    let (length, rest) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), rest)
    } else {
        let count = usize::from(len_byte & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| acc << 8 | usize::from(b));
        if length < 128 || length >> ((count - 1) * 8) == 0 {
            return None;
        }
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| rest.split_at(length))
}

fn cb_sequence(bytes: &[u8]) -> Option<&[u8]> {
    cb_element(bytes, 0x30).map(|(contents, _)| contents)
}

/// cryptobyte's `ReadASN1Integer` into a `big.Int`.
fn cb_integer(bytes: &[u8]) -> Option<(BigInt, &[u8])> {
    let (contents, rest) = cb_element(bytes, 0x02)?;
    check_integer(contents).ok()?;
    Some((BigInt::from_signed_bytes_be(contents), rest))
}

/// cryptobyte's `ReadASN1ObjectIdentifier`.
fn cb_oid(bytes: &[u8]) -> Option<Vec<u32>> {
    let (mut contents, _) = cb_element(bytes, 0x06)?;
    if contents.is_empty() {
        return None;
    }
    let mut components = Vec::new();
    while !contents.is_empty() {
        let (value, rest) = cb_base128(contents)?;
        contents = rest;
        if components.is_empty() {
            if value < 80 {
                components.extend([value / 40, value % 40]);
            } else {
                components.extend([2, value - 80]);
            }
        } else {
            components.push(value);
        }
    }
    Some(components)
}

/// cryptobyte's `readBase128Int`.
fn cb_base128(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let mut value: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i == 5 || value >= 1 << (31 - 7) {
            return None;
        }
        if i == 0 && b == 0x80 {
            return None;
        }
        value = value << 7 | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, &bytes[i + 1..]));
        }
    }
    None
}

// ---- net/netip -----------------------------------------------------------------

/// `netip.ParsePrefix`, the address as written: no zone, bits without a
/// sign or a leading zero.
fn parse_prefix(text: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = text.rsplit_once('/')?;
    let (addr, zone) = parse_addr_zone(addr)?;
    if zone {
        return None;
    }
    if bits.len() > 1 && !matches!(bits.as_bytes()[0], b'1'..=b'9') {
        return None;
    }
    if !bits.bytes().all(|b| b.is_ascii_digit()) || bits.is_empty() {
        return None;
    }
    let bits: u32 = bits.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((addr, bits as u8))
}

/// `netip.ParseAddr` without its zone, which `PrefixFrom` drops.
fn parse_addr(text: &str) -> Option<IpAddr> {
    parse_addr_zone(text).map(|(addr, _)| addr)
}

/// The address and whether it carried a zone.
fn parse_addr_zone(text: &str) -> Option<(IpAddr, bool)> {
    if text.contains(':') {
        let (addr, zone) = match text.split_once('%') {
            Some((_, "")) => return None,
            Some((addr, _)) => (addr, true),
            None => (text, false),
        };
        return addr
            .parse::<Ipv6Addr>()
            .ok()
            .map(|addr| (IpAddr::V6(addr), zone));
    }
    text.parse::<Ipv4Addr>()
        .ok()
        .map(|addr| (IpAddr::V4(addr), false))
}

#[cfg(test)]
mod tests {
    //! What Xray-core's own `infra/conf` makes of each input
    //! (`tools/masque-oracle/warp_conf_oracle_test.go`).
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/masque/warp-config-vectors.json"
        ))
        .unwrap()
    }

    /// An input as the fixture stores it: XOR 0x5a, in hex.
    fn text(case: &Value) -> String {
        let hex = case["input"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap() ^ 0x5a)
            .collect();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn mapped_addresses_count_as_ipv6_as_in_go() {
        // netip keeps ::ffff:a00:1 an IPv6 address: it takes the IPv6 slot.
        let both = addresses(&["::ffff:a00:1".to_owned(), "10.0.0.1".to_owned()]).unwrap();
        assert_eq!(both[0], ("::ffff:a00:1".parse().unwrap(), 128));
        assert!(both[0].0.is_ipv6());
        assert!(addresses(&["::ffff:a00:1".to_owned(), "fd00::1".to_owned()]).is_err());
    }

    #[test]
    fn private_keys_are_read_as_xray_reads_them() {
        let (mut taken, mut refused) = (0, 0);
        for case in vectors()["private"].as_array().unwrap() {
            let input = text(case);
            match (private_key(&input), case["scalar"].as_str()) {
                (Ok(scalar), Some(want)) => {
                    taken += 1;
                    let got: String = scalar.iter().map(|b| format!("{b:02x}")).collect();
                    assert_eq!(got, want, "{input:?}");
                }
                (Err(_), None) => refused += 1,
                (got, want) => panic!("{input:?}: got {:?}, Xray {want:?}", got.err()),
            }
        }
        assert!(
            taken > 50 && refused > 50,
            "{taken} taken, {refused} refused"
        );
    }

    #[test]
    fn public_keys_are_read_as_xray_reads_them() {
        for case in vectors()["public"].as_array().unwrap() {
            let input = text(case);
            assert_eq!(
                public_key(&input).is_ok(),
                case["ok"].as_bool().unwrap(),
                "{input:?}"
            );
        }
    }

    #[test]
    fn addresses_are_read_as_xray_reads_them() {
        for case in vectors()["addresses"].as_array().unwrap() {
            let input: Vec<String> = case["input"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect();
            let got = addresses(&input).map(|list| {
                list.iter()
                    .map(|(addr, len)| format!("{addr}/{len}"))
                    .collect::<Vec<_>>()
            });
            match (got, case["ok"].as_bool().unwrap()) {
                (Ok(got), true) => {
                    let want: Vec<&str> = case["output"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap())
                        .collect();
                    assert_eq!(got, want, "{input:?}");
                }
                (Err(_), false) => {}
                (got, _) => panic!("{input:?}: {got:?}"),
            }
        }
    }
}
