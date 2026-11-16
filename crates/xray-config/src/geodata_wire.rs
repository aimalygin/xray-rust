//! Zero-copy reading of the geodata protobuf messages.
//!
//! Decoding a geosite entry with prost allocates a `String` per domain and a
//! `Vec` per attribute list, tens of thousands of small allocations for a
//! large category, only to copy each name once more into a matcher. These
//! readers borrow the names from the entry body instead.
//!
//! They accept only plain bodies: every known field has the wire type its
//! schema declares, strings are UTF-8, and unknown fields are varints,
//! fixed-size values or length-delimited values. On such a body they yield
//! exactly the values prost decodes, the last occurrence of a repeated scalar
//! field winning as in protobuf. Anything else, such as a group, a mistyped
//! known field or a truncated value, is [`Unsupported`], and the caller
//! decodes the body with prost, which accepts or rejects it with its own
//! errors as before.

use std::str;

/// The body is not plain protobuf; decode it with prost instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unsupported;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

/// The fields of one message, in wire order.
struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }

    /// Returns the next field, `None` at the end of the body.
    fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, Unsupported> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let key = u32::try_from(key).map_err(|_| Unsupported)?;
        let field = key >> 3;
        if field == 0 {
            return Err(Unsupported);
        }
        let value = match key & 0x07 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let len = usize::try_from(self.varint()?).map_err(|_| Unsupported)?;
                Value::Bytes(self.take(len)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            _ => return Err(Unsupported),
        };
        Ok(Some((field, value)))
    }

    /// A varint as prost reads it: at most ten bytes, the tenth below 2.
    fn varint(&mut self) -> Result<u64, Unsupported> {
        let mut value = 0_u64;
        for (index, byte) in self.rest.iter().take(10).enumerate() {
            if index == 9 && *byte > 1 {
                return Err(Unsupported);
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                self.rest = &self.rest[index + 1..];
                return Ok(value);
            }
        }
        Err(Unsupported)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Unsupported> {
        if len > self.rest.len() {
            return Err(Unsupported);
        }
        let (value, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(value)
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, Unsupported> {
    str::from_utf8(bytes).map_err(|_| Unsupported)
}

/// One `GeoSite.domain` record, borrowed from the entry body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Domain<'a> {
    pub(crate) kind: i32,
    pub(crate) value: &'a str,
    body: &'a [u8],
}

impl<'a> Domain<'a> {
    /// Reads `Domain { type = 1; value = 2; repeated attribute = 3 }`.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, Unsupported> {
        let mut kind = 0;
        let mut value = "";
        let mut fields = Fields::new(body);
        while let Some((field, field_value)) = fields.next_field()? {
            match (field, field_value) {
                // prost reads an `int32` enum by truncating the varint.
                (1, Value::Varint(raw)) => kind = raw as i32,
                (2, Value::Bytes(bytes)) => value = utf8(bytes)?,
                (3, Value::Bytes(bytes)) => {
                    attribute_key(bytes)?;
                }
                (1..=3, _) => return Err(Unsupported),
                _ => {}
            }
        }
        Ok(Self { kind, value, body })
    }

    /// The `key` of every attribute, in order. The record was checked by
    /// [`Self::parse`], so no attribute is skipped.
    pub(crate) fn attribute_keys(&self) -> impl Iterator<Item = &'a str> {
        let mut fields = Fields::new(self.body);
        std::iter::from_fn(move || loop {
            match fields.next_field().ok()?? {
                (3, Value::Bytes(bytes)) => return attribute_key(bytes).ok(),
                _ => continue,
            }
        })
    }
}

/// Reads `Attribute { key = 1; ... }`; the typed value is not used.
fn attribute_key(body: &[u8]) -> Result<&str, Unsupported> {
    let mut key = "";
    let mut fields = Fields::new(body);
    while let Some((field, value)) = fields.next_field()? {
        match (field, value) {
            (1, Value::Bytes(bytes)) => key = utf8(bytes)?,
            (1, _) => return Err(Unsupported),
            _ => {}
        }
    }
    Ok(key)
}

/// Checks a whole `GeoSite { code = 1; repeated domain = 2 }` body, every
/// domain record included, and returns its code.
pub(crate) fn site_code(body: &[u8]) -> Result<&str, Unsupported> {
    let mut code = "";
    let mut fields = Fields::new(body);
    while let Some((field, value)) = fields.next_field()? {
        match (field, value) {
            (1, Value::Bytes(bytes)) => code = utf8(bytes)?,
            (2, Value::Bytes(bytes)) => {
                Domain::parse(bytes)?;
            }
            (1 | 2, _) => return Err(Unsupported),
            _ => {}
        }
    }
    Ok(code)
}

/// The domain records of a body that [`site_code`] accepted, in order.
pub(crate) fn site_domains(body: &[u8]) -> impl Iterator<Item = Result<Domain<'_>, Unsupported>> {
    let mut fields = Fields::new(body);
    std::iter::from_fn(move || loop {
        match fields.next_field() {
            Ok(Some((2, Value::Bytes(bytes)))) => return Some(Domain::parse(bytes)),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        }
    })
}

/// One `GeoIP.cidr` record, borrowed from the entry body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr<'a> {
    pub(crate) ip: &'a [u8],
    pub(crate) prefix: u32,
}

impl<'a> Cidr<'a> {
    /// Reads `CIDR { bytes ip = 1; uint32 prefix = 2 }`.
    fn parse(body: &'a [u8]) -> Result<Self, Unsupported> {
        let mut cidr = Self { ip: &[], prefix: 0 };
        let mut fields = Fields::new(body);
        while let Some((field, value)) = fields.next_field()? {
            match (field, value) {
                (1, Value::Bytes(bytes)) => cidr.ip = bytes,
                // prost reads a `uint32` by truncating the varint.
                (2, Value::Varint(raw)) => cidr.prefix = raw as u32,
                (1 | 2, _) => return Err(Unsupported),
                _ => {}
            }
        }
        Ok(cidr)
    }
}

/// The scalar fields of a checked `GeoIP` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GeoIpHeader<'a> {
    pub(crate) code: &'a str,
    pub(crate) reverse_match: bool,
}

/// Checks a whole `GeoIP { code = 1; repeated cidr = 2; reverse_match = 3 }`
/// body, every CIDR record included.
pub(crate) fn geoip_header(body: &[u8]) -> Result<GeoIpHeader<'_>, Unsupported> {
    let mut header = GeoIpHeader {
        code: "",
        reverse_match: false,
    };
    let mut fields = Fields::new(body);
    while let Some((field, value)) = fields.next_field()? {
        match (field, value) {
            (1, Value::Bytes(bytes)) => header.code = utf8(bytes)?,
            (2, Value::Bytes(bytes)) => {
                Cidr::parse(bytes)?;
            }
            (3, Value::Varint(raw)) => header.reverse_match = raw != 0,
            (1..=3, _) => return Err(Unsupported),
            _ => {}
        }
    }
    Ok(header)
}

/// The CIDR records of a body that [`geoip_header`] accepted, in order.
pub(crate) fn geoip_cidrs(body: &[u8]) -> impl Iterator<Item = Result<Cidr<'_>, Unsupported>> {
    let mut fields = Fields::new(body);
    std::iter::from_fn(move || loop {
        match fields.next_field() {
            Ok(Some((2, Value::Bytes(bytes)))) => return Some(Cidr::parse(bytes)),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(error) => return Some(Err(error)),
        }
    })
}
