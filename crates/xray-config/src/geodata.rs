use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use prost::Message;
use thiserror::Error;

use crate::{ConfigModelError, DomainMatcher, IpCidr, IpMatcher, RegexMatcher};

#[derive(Debug, Clone)]
pub(crate) struct GeodataLoader {
    search_dirs: Vec<PathBuf>,
    sites: HashMap<GeodataCacheKey, GeoSite>,
    ips: HashMap<GeodataCacheKey, GeoIp>,
}

impl Default for GeodataLoader {
    fn default() -> Self {
        Self::from_dirs(default_geodata_dirs())
    }
}

impl GeodataLoader {
    pub(crate) fn from_dirs(search_dirs: Vec<PathBuf>) -> Self {
        Self {
            search_dirs,
            sites: HashMap::new(),
            ips: HashMap::new(),
        }
    }

    pub(crate) fn load_site_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        attrs: &[String],
    ) -> Result<Vec<DomainMatcher>, GeodataError> {
        let code = normalize_code(code);
        let site = self.load_site(file_name, &code)?;
        let mut matchers = Vec::new();

        for domain in &site.domain {
            if domain_matches_attrs(domain, attrs) {
                matchers.push(domain_to_matcher(domain, file_name, &code)?);
            }
        }

        Ok(matchers)
    }

    pub(crate) fn load_ip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
    ) -> Result<Vec<IpMatcher>, GeodataError> {
        let code = normalize_code(code);
        let geoip = self.load_ip(file_name, &code)?;
        let inverse = inverse ^ geoip.reverse_match;
        geoip
            .cidr
            .iter()
            .map(|cidr| {
                let matcher = IpMatcher::Cidr(cidr_to_ip_cidr(cidr, file_name, &code)?);
                Ok(wrap_inverse(matcher, inverse))
            })
            .collect()
    }

    fn load_site(&mut self, file_name: &str, code: &str) -> Result<GeoSite, GeodataError> {
        let key = GeodataCacheKey::new(file_name, code);
        if let Some(site) = self.sites.get(&key) {
            return Ok(site.clone());
        }

        let site = self.load_entry::<GeoSite>(file_name, code)?;
        self.sites.insert(key, site.clone());
        Ok(site)
    }

    fn load_ip(&mut self, file_name: &str, code: &str) -> Result<GeoIp, GeodataError> {
        let key = GeodataCacheKey::new(file_name, code);
        if let Some(geoip) = self.ips.get(&key) {
            return Ok(geoip.clone());
        }

        let geoip = self.load_entry::<GeoIp>(file_name, code)?;
        self.ips.insert(key, geoip.clone());
        Ok(geoip)
    }

    fn load_entry<M>(&self, file_name: &str, code: &str) -> Result<M, GeodataError>
    where
        M: Message + Default,
    {
        let path = self.resolve_file_path(file_name)?;
        let body = find_entry_body(&path, code)?.ok_or_else(|| GeodataError::CodeNotFound {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
        })?;

        M::decode(body.as_slice()).map_err(|source| GeodataError::Decode { path, source })
    }

    fn resolve_file_path(&self, file_name: &str) -> Result<PathBuf, GeodataError> {
        let requested = Path::new(file_name);
        if requested.is_absolute() {
            if requested.is_file() {
                return Ok(requested.to_path_buf());
            }

            return Err(GeodataError::FileNotFound {
                file_name: file_name.to_owned(),
                searched: vec![requested.to_path_buf()],
            });
        }

        let mut searched = Vec::new();
        for dir in &self.search_dirs {
            let candidate = dir.join(requested);
            searched.push(candidate.clone());
            if candidate.is_file() {
                return Ok(candidate);
            }
        }

        Err(GeodataError::FileNotFound {
            file_name: file_name.to_owned(),
            searched,
        })
    }
}

pub(crate) fn default_geodata_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(executable_dir) = executable.parent() {
            let executable_dir = executable_dir.to_path_buf();
            if !dirs.iter().any(|dir| dir == &executable_dir) {
                dirs.push(executable_dir);
            }
        }
    }
    dirs.push(PathBuf::from("."));
    dirs
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GeodataCacheKey {
    file_name: String,
    code: String,
}

impl GeodataCacheKey {
    fn new(file_name: &str, code: &str) -> Self {
        Self {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum GeodataError {
    #[error("geodata file `{file_name}` was not found; searched: {searched:?}")]
    FileNotFound {
        file_name: String,
        searched: Vec<PathBuf>,
    },
    #[error("failed to read geodata file `{path}`: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("invalid geodata file `{path}`: {message}")]
    InvalidFile { path: PathBuf, message: String },
    #[error("failed to decode geodata file `{path}`: {source}")]
    Decode {
        path: PathBuf,
        source: prost::DecodeError,
    },
    #[error("geodata file `{file_name}` does not contain code `{code}`")]
    CodeNotFound { file_name: String, code: String },
    #[error("unsupported geosite domain type {domain_type} in `{file_name}:{code}`")]
    UnsupportedDomainType {
        file_name: String,
        code: String,
        domain_type: i32,
    },
    #[error("invalid geosite domain in `{file_name}:{code}`: {message}")]
    InvalidDomain {
        file_name: String,
        code: String,
        message: String,
    },
    #[error("invalid geosite domain matcher in `{file_name}:{code}`: {source}")]
    InvalidDomainMatcher {
        file_name: String,
        code: String,
        source: ConfigModelError,
    },
    #[error("invalid geoip CIDR in `{file_name}:{code}`: {message}")]
    InvalidCidr {
        file_name: String,
        code: String,
        message: String,
    },
}

fn find_entry_body(path: &Path, code: &str) -> Result<Option<Vec<u8>>, GeodataError> {
    let file = File::open(path).map_err(|source| GeodataError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);

    loop {
        let mut ignored_prefix = [0_u8; 1];
        match reader.read_exact(&mut ignored_prefix) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(source) => {
                return Err(GeodataError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }

        let body_len = read_varint(&mut reader).map_err(|source| GeodataError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let body_len = usize::try_from(body_len).map_err(|_| GeodataError::InvalidFile {
            path: path.to_path_buf(),
            message: "geodata entry body is too large".to_owned(),
        })?;

        let mut body = vec![0_u8; body_len];
        reader
            .read_exact(&mut body)
            .map_err(|source| GeodataError::Read {
                path: path.to_path_buf(),
                source,
            })?;

        if body_starts_with_code(&body, code) {
            return Ok(Some(body));
        }
    }
}

fn read_varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte)?;
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }

    Err(io::Error::new(
        ErrorKind::InvalidData,
        "geodata entry length varint is too long",
    ))
}

fn body_starts_with_code(body: &[u8], code: &str) -> bool {
    let Some((&field_tag, rest)) = body.split_first() else {
        return false;
    };
    if field_tag != 0x0a {
        return false;
    }

    let Some((code_len, varint_len)) = decode_varint_from_slice(rest) else {
        return false;
    };
    let Ok(code_len) = usize::try_from(code_len) else {
        return false;
    };
    let code_start = 1 + varint_len;
    let code_end = code_start + code_len;

    body.get(code_start..code_end) == Some(code.as_bytes())
}

fn decode_varint_from_slice(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().take(10).enumerate() {
        value |= u64::from(*byte & 0x7f) << (index * 7);
        if *byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }

    None
}

fn domain_matches_attrs(domain: &GeoDomain, attrs: &[String]) -> bool {
    attrs.iter().all(|attr| {
        domain
            .attribute
            .iter()
            .any(|candidate| candidate.key.eq_ignore_ascii_case(attr))
    })
}

fn domain_to_matcher(
    domain: &GeoDomain,
    file_name: &str,
    code: &str,
) -> Result<DomainMatcher, GeodataError> {
    if domain.value.is_empty() {
        return Err(GeodataError::InvalidDomain {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
            message: "domain value cannot be empty".to_owned(),
        });
    }

    let domain_type = GeoDomainType::try_from(domain.r#type).map_err(|_| {
        GeodataError::UnsupportedDomainType {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
            domain_type: domain.r#type,
        }
    })?;

    match domain_type {
        GeoDomainType::Substr => Ok(DomainMatcher::Keyword(domain.value.clone())),
        GeoDomainType::Regex => RegexMatcher::new(domain.value.clone())
            .map(DomainMatcher::Regex)
            .map_err(|source| GeodataError::InvalidDomainMatcher {
                file_name: file_name.to_owned(),
                code: code.to_owned(),
                source,
            }),
        GeoDomainType::Domain => Ok(DomainMatcher::Suffix(domain.value.clone())),
        GeoDomainType::Full => Ok(DomainMatcher::Full(domain.value.clone())),
    }
}

fn cidr_to_ip_cidr(cidr: &GeoCidr, file_name: &str, code: &str) -> Result<IpCidr, GeodataError> {
    let ip = match cidr.ip.as_slice() {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        bytes if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => {
            return Err(GeodataError::InvalidCidr {
                file_name: file_name.to_owned(),
                code: code.to_owned(),
                message: format!("IP byte slice must be 4 or 16 bytes, got {}", cidr.ip.len()),
            });
        }
    };

    let prefix = u8::try_from(cidr.prefix).map_err(|_| GeodataError::InvalidCidr {
        file_name: file_name.to_owned(),
        code: code.to_owned(),
        message: format!("CIDR prefix length {} does not fit in u8", cidr.prefix),
    })?;

    IpCidr::new(ip, prefix).map_err(|source| GeodataError::InvalidCidr {
        file_name: file_name.to_owned(),
        code: code.to_owned(),
        message: source.to_string(),
    })
}

fn wrap_inverse(matcher: IpMatcher, inverse: bool) -> IpMatcher {
    if inverse {
        IpMatcher::Not(Box::new(matcher))
    } else {
        matcher
    }
}

fn normalize_code(code: &str) -> String {
    code.to_ascii_uppercase()
}

#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<GeoDomain>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoDomain {
    #[prost(enumeration = "GeoDomainType", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<GeoDomainAttribute>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoDomainAttribute {
    #[prost(string, tag = "1")]
    key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum GeoDomainType {
    Substr = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<GeoCidr>,
    #[prost(bool, tag = "3")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct GeoCidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_geodata_dirs_include_current_executable_directory() {
        let executable_dir = std::env::current_exe()
            .expect("current executable path should be available")
            .parent()
            .expect("current executable should have a parent directory")
            .to_path_buf();

        assert!(super::default_geodata_dirs()
            .iter()
            .any(|dir| dir == &executable_dir));
    }
}
