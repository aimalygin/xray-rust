//! A domain the client tunnels under, as Xray-core's `NewDomain` reads it,
//! and the names it writes and reads under it.
use super::XdnsError;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_AAAA: u16 = 28;

/// The two low bits of the client id's first byte name the query's type.
pub(crate) fn type_bits(qtype: u16) -> u8 {
    match qtype {
        TYPE_A => 0,
        TYPE_CNAME => 1,
        TYPE_TXT => 2,
        _ => 3,
    }
}

/// Go's `base32.StdEncoding`, which xdns uses without padding and in lower
/// case on the wire.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `base32.NoPadding`'s `DecodedLen`.
fn decoded_len(n: usize) -> usize {
    n * 5 / 8
}

/// `base32.NoPadding`'s `EncodedLen`.
fn encoded_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

/// One domain's name and what fits under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Domain {
    /// The name as Go's `dnsmessage.Name` holds it: the configured bytes
    /// and a trailing dot.
    name: Vec<u8>,
    label_limit: usize,
    types: Vec<u16>,
    edns0: u16,
    /// The bytes one query's name carries.
    capacity: usize,
}

impl Domain {
    /// `NewDomain` without its IDNA check, which the configuration makes.
    /// It also refuses what Go accepts and then fails to pack, panicking at
    /// the first query: an empty label or one longer than 63 bytes.
    pub(crate) fn new(
        name: &str,
        len_limit: i32,
        label_limit: i32,
        types: &[u16],
        edns0: u16,
    ) -> Result<Self, XdnsError> {
        if name.contains("..") {
            return Err(XdnsError::Domain("the domain has an empty label"));
        }
        let len_limit = usize::try_from(len_limit)
            .ok()
            .filter(|limit| *limit <= 255)
            .ok_or(XdnsError::Domain("lenLimit must be 0 to 255"))?;
        let label_limit = usize::try_from(label_limit)
            .ok()
            .filter(|limit| *limit <= 63)
            .ok_or(XdnsError::Domain("labelLimit must be 0 to 63"))?;
        if types.is_empty() {
            return Err(XdnsError::Domain("a domain needs a record type"));
        }
        if types
            .iter()
            .any(|t| ![TYPE_A, TYPE_CNAME, TYPE_TXT, TYPE_AAAA].contains(t))
        {
            return Err(XdnsError::Domain(
                "record types must be A (1), CNAME (5), TXT (16) or AAAA (28)",
            ));
        }
        if edns0 != 0 && !(512..=4096).contains(&edns0) {
            return Err(XdnsError::Domain("edns0 must be 0 or 512 to 4096"));
        }
        if name.is_empty()
            || name
                .split('.')
                .any(|label| label.is_empty() || label.len() > 63)
        {
            return Err(XdnsError::Domain(
                "every label of the domain must be 1 to 63 bytes",
            ));
        }
        let mut wire = name.as_bytes().to_vec();
        wire.push(b'.');
        if wire.len() > 255 {
            return Err(XdnsError::Domain("the domain is longer than 254 bytes"));
        }
        if len_limit < wire.len() + 1 {
            return Err(XdnsError::Domain("lenLimit is shorter than the domain"));
        }
        let room = len_limit - wire.len() - 1;
        let labels = room / (label_limit + 1);
        let left = room % (label_limit + 1);
        let mut total = labels * label_limit;
        if left > 1 {
            total += left - 1;
        }
        let capacity = decoded_len(total);
        if capacity < 17 {
            return Err(XdnsError::Domain(
                "lenLimit and labelLimit leave a query under 17 bytes",
            ));
        }
        Ok(Self {
            name: wire,
            label_limit,
            types: types.to_vec(),
            edns0,
            capacity,
        })
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn types(&self) -> &[u16] {
        &self.types
    }

    pub(crate) fn edns0(&self) -> u16 {
        self.edns0
    }

    pub(crate) fn has_type(&self, qtype: u16) -> bool {
        self.types.contains(&qtype)
    }

    /// `IsDomain`: whether `name` is longer than the domain and ends in it,
    /// whatever the ASCII case, label boundary or not.
    pub(crate) fn is_domain(&self, name: &[u8]) -> bool {
        name.len() > self.name.len()
            && name[name.len() - self.name.len()..].eq_ignore_ascii_case(&self.name)
    }

    /// `Encode`: `data` in lower-case base32, in labels of `labelLimit`
    /// characters, under the domain. The caller keeps `data` within the
    /// capacity.
    pub(crate) fn encode(&self, data: &[u8]) -> Vec<u8> {
        let encoded = base32_encode(data);
        let mut name = Vec::with_capacity(
            encoded.len() + encoded.len() / self.label_limit + 1 + self.name.len(),
        );
        for label in encoded.chunks(self.label_limit) {
            name.extend(label.iter().map(u8::to_ascii_lowercase));
            name.push(b'.');
        }
        name.extend_from_slice(&self.name);
        name
    }

    /// `Decode`: what a name under the domain carries, or nothing.
    pub(crate) fn decode(&self, name: &[u8]) -> Vec<u8> {
        if !self.is_domain(name) {
            return Vec::new();
        }
        let encoded: Vec<u8> = name[..name.len() - self.name.len()]
            .iter()
            .filter(|&&byte| byte != b'.')
            .map(u8::to_ascii_uppercase)
            .collect();
        base32_decode(&encoded).unwrap_or_default()
    }
}

fn base32_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded_len(data.len()));
    for chunk in data.chunks(5) {
        let mut block = [0u8; 5];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, block[0], block[1], block[2], block[3], block[4]]);
        let chars = encoded_len(chunk.len());
        for i in 0..chars {
            out.push(ALPHABET[(bits >> (35 - 5 * i) & 31) as usize]);
        }
    }
    out
}

/// Go's `base32.StdEncoding.WithPadding(base32.NoPadding).Decode`, quirks
/// and all: carriage returns and line feeds are skipped; a final group of
/// one, three or six characters yields nothing rather than an error; and
/// since `byte(NoPadding)` is 0xFF, a 0xFF byte near the end is read as
/// padding.
fn base32_decode(input: &[u8]) -> Option<Vec<u8>> {
    const PAD: u8 = 0xFF;
    let src: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&byte| byte != b'\r' && byte != b'\n')
        .collect();
    let mut src = &src[..];
    let mut out = Vec::with_capacity(decoded_len(src.len()));
    let mut end = false;
    while !src.is_empty() && !end {
        let mut block = [0u8; 8];
        let mut length = 8;
        let mut j = 0;
        while j < 8 {
            let Some((&byte, rest)) = src.split_first() else {
                length = j;
                end = true;
                break;
            };
            src = rest;
            if byte == PAD && j >= 2 && src.len() < 8 {
                if src.len() + j < 7 {
                    return None;
                }
                for k in 0..7 - j {
                    if src.len() > k && src[k] != PAD {
                        return None;
                    }
                }
                length = j;
                end = true;
                if matches!(length, 1 | 3 | 6) {
                    return None;
                }
                break;
            }
            block[j] = ALPHABET.iter().position(|&c| c == byte)? as u8;
            j += 1;
        }
        let bits = block
            .iter()
            .fold(0u64, |acc, &value| acc << 5 | u64::from(value));
        let bytes = match length {
            8 => 5,
            7 => 4,
            5 => 3,
            4 => 2,
            2 => 1,
            _ => 0,
        };
        for i in 0..bytes {
            out.push((bits >> (32 - 8 * i)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests;
