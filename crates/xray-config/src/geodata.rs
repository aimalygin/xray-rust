use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use prost::Message;
use thiserror::Error;

use crate::{ConfigModelError, DomainMatcher, IpCidr, IpMatcher, RegexMatcher};

const MAX_GEODATA_FILE_SIZE: u64 = 128 * 1024 * 1024;
const MAX_GEODATA_ENTRY_SIZE: usize = 32 * 1024 * 1024;
const MAX_GEODATA_INDEX_ENTRIES: usize = 65_536;
const MAX_GEODATA_INDEX_CODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_GEODATA_CODE_SIZE: usize = 256;
const MAX_GEODATA_DOMAINS: usize = 200_000;
const MAX_GEODATA_DOMAIN_ATTRIBUTES: usize = 400_000;
const MAX_GEODATA_DOMAIN_VALUE_SIZE: usize = 4 * 1024;
const MAX_GEODATA_ATTRIBUTE_SIZE: usize = 1024;
const MAX_GEODATA_CIDRS: usize = 250_000;
const MAX_GEODATA_CIDR_SIZE: usize = 128;

#[derive(Debug)]
pub(crate) struct GeodataLoader {
    search_dirs: Vec<PathBuf>,
    files: HashMap<String, IndexedGeodataFile>,
    sites: HashMap<GeodataCacheKey, Arc<GeoSite>>,
    ips: HashMap<GeodataCacheKey, Arc<GeoIp>>,
    site_selections: HashMap<GeositeSelectionKey, Arc<[usize]>>,
    #[cfg(test)]
    index_builds: usize,
    #[cfg(test)]
    domain_matcher_builds: usize,
    #[cfg(test)]
    ip_matcher_builds: usize,
    #[cfg(test)]
    domain_filter_scans: usize,
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
            files: HashMap::new(),
            sites: HashMap::new(),
            ips: HashMap::new(),
            site_selections: HashMap::new(),
            #[cfg(test)]
            index_builds: 0,
            #[cfg(test)]
            domain_matcher_builds: 0,
            #[cfg(test)]
            ip_matcher_builds: 0,
            #[cfg(test)]
            domain_filter_scans: 0,
        }
    }

    pub(crate) fn load_site_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        attrs: &[String],
        max_matchers: usize,
    ) -> Result<Vec<DomainMatcher>, GeodataError> {
        let code = normalize_code(code);
        let site = self.load_site(file_name, &code)?;
        if attrs.is_empty() {
            self.ensure_domain_matcher_budget(file_name, &code, site.domain.len(), max_matchers)?;
            let mut matchers = Vec::with_capacity(site.domain.len());
            for domain in &site.domain {
                matchers.push(domain_to_matcher(domain, file_name, &code)?);
                self.record_domain_matcher_build();
            }
            return Ok(matchers);
        }

        let selection_key = GeositeSelectionKey::new(file_name, &code, attrs);
        let selected = match self.site_selections.get(&selection_key) {
            Some(selected) => Arc::clone(selected),
            None => {
                let mut selected = Vec::new();
                for (index, domain) in site.domain.iter().enumerate() {
                    #[cfg(test)]
                    {
                        self.domain_filter_scans += 1;
                    }
                    if domain_matches_attrs(domain, attrs) {
                        if selected.len() == max_matchers {
                            return Err(GeodataError::DomainMatcherBudgetExceeded {
                                file_name: file_name.to_owned(),
                                code,
                                expanded: max_matchers.saturating_add(1),
                                remaining: max_matchers,
                            });
                        }
                        selected.push(index);
                    }
                }
                let selected = Arc::<[usize]>::from(selected);
                self.site_selections
                    .insert(selection_key, Arc::clone(&selected));
                selected
            }
        };
        self.ensure_domain_matcher_budget(file_name, &code, selected.len(), max_matchers)?;

        let mut matchers = Vec::with_capacity(selected.len());
        for &index in selected.iter() {
            matchers.push(domain_to_matcher(&site.domain[index], file_name, &code)?);
            self.record_domain_matcher_build();
        }

        Ok(matchers)
    }

    fn ensure_domain_matcher_budget(
        &self,
        file_name: &str,
        code: &str,
        matcher_count: usize,
        max_matchers: usize,
    ) -> Result<(), GeodataError> {
        if matcher_count > max_matchers {
            return Err(GeodataError::DomainMatcherBudgetExceeded {
                file_name: file_name.to_owned(),
                code: code.to_owned(),
                expanded: matcher_count,
                remaining: max_matchers,
            });
        }
        Ok(())
    }

    fn record_domain_matcher_build(&mut self) {
        #[cfg(test)]
        {
            self.domain_matcher_builds += 1;
        }
    }

    pub(crate) fn load_ip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        max_matchers: usize,
    ) -> Result<Vec<IpMatcher>, GeodataError> {
        let code = normalize_code(code);
        let geoip = self.load_ip(file_name, &code)?;
        if geoip.cidr.len() > max_matchers {
            return Err(GeodataError::IpMatcherBudgetExceeded {
                file_name: file_name.to_owned(),
                code,
                expanded: geoip.cidr.len(),
                remaining: max_matchers,
            });
        }
        let inverse = inverse ^ geoip.reverse_match;
        geoip
            .cidr
            .iter()
            .map(|cidr| {
                let matcher = IpMatcher::Cidr(cidr_to_ip_cidr(cidr, file_name, &code)?);
                #[cfg(test)]
                {
                    self.ip_matcher_builds += 1;
                }
                Ok(wrap_inverse(matcher, inverse))
            })
            .collect()
    }

    fn load_site(&mut self, file_name: &str, code: &str) -> Result<Arc<GeoSite>, GeodataError> {
        let key = GeodataCacheKey::new(file_name, code);
        if let Some(site) = self.sites.get(&key) {
            return Ok(Arc::clone(site));
        }

        let site = Arc::new(self.load_entry::<GeoSite>(
            file_name,
            code,
            validate_geo_site_body,
            |site| &site.code,
        )?);
        self.sites.insert(key, Arc::clone(&site));
        Ok(site)
    }

    fn load_ip(&mut self, file_name: &str, code: &str) -> Result<Arc<GeoIp>, GeodataError> {
        let key = GeodataCacheKey::new(file_name, code);
        if let Some(geoip) = self.ips.get(&key) {
            return Ok(Arc::clone(geoip));
        }

        let geoip = Arc::new(self.load_entry::<GeoIp>(
            file_name,
            code,
            validate_geo_ip_body,
            |geoip| &geoip.code,
        )?);
        self.ips.insert(key, Arc::clone(&geoip));
        Ok(geoip)
    }

    fn load_entry<M>(
        &mut self,
        file_name: &str,
        code: &str,
        validate_body: fn(&[u8]) -> Result<(), String>,
        decoded_code: fn(&M) -> &str,
    ) -> Result<M, GeodataError>
    where
        M: Message + Default,
    {
        if !self.files.contains_key(file_name) {
            let (file, path) = self.open_file(file_name)?;
            let indexed = IndexedGeodataFile::new(file, path)?;
            self.files.insert(file_name.to_owned(), indexed);
            #[cfg(test)]
            {
                self.index_builds += 1;
            }
        }

        let indexed = self
            .files
            .get_mut(file_name)
            .expect("geodata file was inserted above");
        let path = indexed.path.clone();
        let body = indexed
            .read_entry(code)?
            .ok_or_else(|| GeodataError::CodeNotFound {
                file_name: file_name.to_owned(),
                code: code.to_owned(),
            })?;
        validate_body(&body).map_err(|message| GeodataError::InvalidFile {
            path: path.clone(),
            message,
        })?;

        let decoded = M::decode(body.as_slice()).map_err(|source| GeodataError::Decode {
            path: path.clone(),
            source,
        })?;
        if decoded_code(&decoded) != code {
            return Err(GeodataError::InvalidFile {
                path,
                message: "decoded geodata code does not match its index entry".to_owned(),
            });
        }
        Ok(decoded)
    }

    fn open_file(&self, file_name: &str) -> Result<(File, PathBuf), GeodataError> {
        let requested = Path::new(file_name);
        if file_name.is_empty()
            || requested.is_absolute()
            || requested
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(GeodataError::InvalidPath {
                file_name: file_name.to_owned(),
                message: "path must contain only normal components relative to a configured geodata directory"
                    .to_owned(),
            });
        }

        let mut searched = Vec::new();
        for dir in &self.search_dirs {
            let candidate = dir.join(requested);
            searched.push(candidate.clone());
            match open_file_beneath(dir, requested) {
                Ok(file) => {
                    let metadata = file.metadata().map_err(|source| GeodataError::Read {
                        path: candidate.clone(),
                        source,
                    })?;
                    if metadata.is_file() {
                        return Ok((file, candidate));
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                #[cfg(unix)]
                Err(error) if matches!(error.raw_os_error(), Some(code) if code == libc::ELOOP || code == libc::ENOTDIR) =>
                {
                    return Err(GeodataError::InvalidPath {
                        file_name: file_name.to_owned(),
                        message: "symbolic links and non-directory path components are not allowed"
                            .to_owned(),
                    });
                }
                Err(source) => {
                    return Err(GeodataError::Read {
                        path: candidate,
                        source,
                    });
                }
            }
        }

        Err(GeodataError::FileNotFound {
            file_name: file_name.to_owned(),
            searched,
        })
    }
}

#[cfg(unix)]
fn open_file_beneath(root: &Path, requested: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let root = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "geodata root contains NUL"))?;
    let root_flags =
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY;
    // SAFETY: `root` is a live NUL-terminated path and the flags request a
    // read-only directory descriptor. The returned fd is uniquely owned.
    let root_fd = unsafe { libc::open(root.as_ptr(), root_flags) };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a fresh owned fd and this is its sole owner.
    let mut current_dir = unsafe { File::from_raw_fd(root_fd) };
    let mut components = requested.components().peekable();
    while let Some(Component::Normal(component)) = components.next() {
        let component = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "geodata path component contains NUL",
            )
        })?;
        let is_last = components.peek().is_none();
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        if !is_last {
            flags |= libc::O_DIRECTORY;
        }
        // SAFETY: `current_dir` owns a live directory fd, `component` is a
        // NUL-terminated single path component, and `flags` request no
        // writable access. A successful fd is transferred to `File` below.
        let fd = unsafe { libc::openat(current_dir.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh owned fd and this is its sole owner.
        let opened = unsafe { File::from_raw_fd(fd) };
        if is_last {
            return Ok(opened);
        }
        current_dir = opened;
    }

    Err(io::Error::new(
        ErrorKind::InvalidInput,
        "geodata path has no file component",
    ))
}

#[cfg(not(unix))]
fn open_file_beneath(root: &Path, requested: &Path) -> io::Result<File> {
    let candidate = root.join(requested);
    let resolved = candidate.canonicalize()?;
    if !resolved.starts_with(root) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "geodata path escapes configured directory",
        ));
    }
    File::open(resolved)
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GeositeSelectionKey {
    file_name: String,
    code: String,
    attrs: Vec<String>,
}

impl GeositeSelectionKey {
    fn new(file_name: &str, code: &str, attrs: &[String]) -> Self {
        Self {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
            attrs: attrs.to_vec(),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum GeodataError {
    #[error("invalid geodata path `{file_name}`: {message}")]
    InvalidPath { file_name: String, message: String },
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
    #[error(
        "geosite `{file_name}:{code}` requires at least {expanded} domain matchers, but only {remaining} slots remain in this configuration's matcher budget"
    )]
    DomainMatcherBudgetExceeded {
        file_name: String,
        code: String,
        expanded: usize,
        remaining: usize,
    },
    #[error(
        "geoip `{file_name}:{code}` expands to {expanded} IP matchers, but only {remaining} slots remain in this configuration's matcher budget"
    )]
    IpMatcherBudgetExceeded {
        file_name: String,
        code: String,
        expanded: usize,
        remaining: usize,
    },
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

#[derive(Debug, Clone, Copy)]
struct GeodataEntryLocation {
    offset: u64,
    len: usize,
}

#[derive(Debug)]
struct IndexedGeodataFile {
    file: File,
    path: PathBuf,
    entries: HashMap<String, GeodataEntryLocation>,
}

impl IndexedGeodataFile {
    fn new(file: File, path: PathBuf) -> Result<Self, GeodataError> {
        let entries = index_geodata_file(&file, &path)?;
        Ok(Self {
            file,
            path,
            entries,
        })
    }

    fn read_entry(&mut self, code: &str) -> Result<Option<Vec<u8>>, GeodataError> {
        let Some(location) = self.entries.get(code).copied() else {
            return Ok(None);
        };
        self.file
            .seek(SeekFrom::Start(location.offset))
            .map_err(|source| GeodataError::Read {
                path: self.path.clone(),
                source,
            })?;
        let mut body = vec![0_u8; location.len];
        self.file
            .read_exact(&mut body)
            .map_err(|source| GeodataError::Read {
                path: self.path.clone(),
                source,
            })?;
        Ok(Some(body))
    }
}

fn index_geodata_file(
    file: &File,
    path: &Path,
) -> Result<HashMap<String, GeodataEntryLocation>, GeodataError> {
    let file_len = file
        .metadata()
        .map_err(|source| GeodataError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if file_len > MAX_GEODATA_FILE_SIZE {
        return Err(GeodataError::InvalidFile {
            path: path.to_path_buf(),
            message: format!(
                "file is {file_len} bytes; maximum supported size is {MAX_GEODATA_FILE_SIZE} bytes"
            ),
        });
    }
    let file = file.try_clone().map_err(|source| GeodataError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut entries = HashMap::new();
    let mut record_count = 0usize;
    let mut indexed_code_bytes = 0usize;

    loop {
        let mut ignored_prefix = [0_u8; 1];
        match reader.read_exact(&mut ignored_prefix) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(entries),
            Err(source) => {
                return Err(GeodataError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        record_count = record_count.saturating_add(1);
        if record_count > MAX_GEODATA_INDEX_ENTRIES {
            return Err(GeodataError::InvalidFile {
                path: path.to_path_buf(),
                message: format!("geodata contains more than {MAX_GEODATA_INDEX_ENTRIES} entries"),
            });
        }

        let body_len = read_varint(&mut reader).map_err(|source| GeodataError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let body_len = usize::try_from(body_len).map_err(|_| GeodataError::InvalidFile {
            path: path.to_path_buf(),
            message: "geodata entry body is too large".to_owned(),
        })?;
        if body_len > MAX_GEODATA_ENTRY_SIZE {
            return Err(GeodataError::InvalidFile {
                path: path.to_path_buf(),
                message: format!(
                    "entry body is {body_len} bytes; maximum supported size is {MAX_GEODATA_ENTRY_SIZE} bytes"
                ),
            });
        }

        let body_offset = reader
            .stream_position()
            .map_err(|source| GeodataError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        body_offset
            .checked_add(body_len as u64)
            .filter(|end| *end <= file_len)
            .ok_or_else(|| GeodataError::InvalidFile {
                path: path.to_path_buf(),
                message: "geodata entry extends beyond the end of the file".to_owned(),
            })?;
        if let Some(code) = scan_entry_code(&mut reader, body_len, path)? {
            if let std::collections::hash_map::Entry::Vacant(entry) = entries.entry(code) {
                indexed_code_bytes = indexed_code_bytes
                    .checked_add(entry.key().len())
                    .ok_or_else(|| GeodataError::InvalidFile {
                        path: path.to_path_buf(),
                        message: "geodata index code size overflow".to_owned(),
                    })?;
                if indexed_code_bytes > MAX_GEODATA_INDEX_CODE_BYTES {
                    return Err(GeodataError::InvalidFile {
                        path: path.to_path_buf(),
                        message: format!(
                            "geodata index code strings exceed {MAX_GEODATA_INDEX_CODE_BYTES} bytes"
                        ),
                    });
                }
                entry.insert(GeodataEntryLocation {
                    offset: body_offset,
                    len: body_len,
                });
            }
        }
    }
}

fn scan_entry_code(
    reader: &mut impl BufRead,
    body_len: usize,
    path: &Path,
) -> Result<Option<String>, GeodataError> {
    let mut remaining = body_len as u64;
    let mut code = None;

    while remaining > 0 {
        let key = read_bounded_varint(reader, &mut remaining, path)?;
        let field = key >> 3;
        if field == 0 {
            return Err(invalid_geodata_file(
                path,
                "protobuf field number cannot be zero",
            ));
        }

        match key & 0x07 {
            0 => {
                read_bounded_varint(reader, &mut remaining, path)?;
            }
            1 => skip_bounded(reader, &mut remaining, 8, path)?,
            2 => {
                let value_len = read_bounded_varint(reader, &mut remaining, path)?;
                if value_len > remaining {
                    return Err(invalid_geodata_file(
                        path,
                        "protobuf field extends beyond the geodata entry",
                    ));
                }
                if field == 1 {
                    let value_len = usize::try_from(value_len).map_err(|_| {
                        invalid_geodata_file(path, "geodata code length does not fit in usize")
                    })?;
                    if value_len > MAX_GEODATA_CODE_SIZE {
                        return Err(invalid_geodata_file(
                            path,
                            format!(
                                "geodata code is {value_len} bytes; maximum supported size is {MAX_GEODATA_CODE_SIZE} bytes"
                            ),
                        ));
                    }
                    let mut bytes = vec![0_u8; value_len];
                    reader
                        .read_exact(&mut bytes)
                        .map_err(|source| GeodataError::Read {
                            path: path.to_path_buf(),
                            source,
                        })?;
                    remaining -= value_len as u64;
                    code = Some(String::from_utf8(bytes).map_err(|_| {
                        invalid_geodata_file(path, "geodata code is not valid UTF-8")
                    })?);
                } else {
                    skip_bounded(reader, &mut remaining, value_len, path)?;
                }
            }
            5 => skip_bounded(reader, &mut remaining, 4, path)?,
            wire_type => {
                return Err(invalid_geodata_file(
                    path,
                    format!("unsupported protobuf wire type {wire_type}"),
                ));
            }
        }
    }

    Ok(code)
}

fn read_bounded_varint(
    reader: &mut impl Read,
    remaining: &mut u64,
    path: &Path,
) -> Result<u64, GeodataError> {
    let mut value = 0_u64;
    for index in 0..10 {
        if *remaining == 0 {
            return Err(invalid_geodata_file(path, "truncated protobuf varint"));
        }
        let mut byte = [0_u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|source| GeodataError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        *remaining -= 1;
        if index == 9 && byte[0] > 1 {
            return Err(invalid_geodata_file(path, "protobuf varint overflows u64"));
        }
        value |= u64::from(byte[0] & 0x7f) << (index * 7);
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid_geodata_file(path, "protobuf varint is too long"))
}

fn skip_bounded(
    reader: &mut impl BufRead,
    remaining: &mut u64,
    amount: u64,
    path: &Path,
) -> Result<(), GeodataError> {
    if amount > *remaining {
        return Err(invalid_geodata_file(
            path,
            "protobuf field extends beyond the geodata entry",
        ));
    }
    let mut unread = amount;
    while unread > 0 {
        let available = reader.fill_buf().map_err(|source| GeodataError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if available.is_empty() {
            return Err(GeodataError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated protobuf length-delimited field",
                ),
            });
        }
        let consumed = available.len().min(unread as usize);
        reader.consume(consumed);
        unread -= consumed as u64;
    }
    *remaining -= amount;
    Ok(())
}

fn invalid_geodata_file(path: &Path, message: impl Into<String>) -> GeodataError {
    GeodataError::InvalidFile {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

#[cfg(test)]
fn find_entry_body(file: File, path: &Path, code: &str) -> Result<Option<Vec<u8>>, GeodataError> {
    IndexedGeodataFile::new(file, path.to_path_buf())?.read_entry(code)
}

fn read_varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte)?;
        if shift == 63 && byte[0] > 1 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "geodata entry length varint overflows u64",
            ));
        }
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

fn decode_varint_from_slice(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().take(10).enumerate() {
        if index == 9 && *byte > 1 {
            return None;
        }
        value |= u64::from(*byte & 0x7f) << (index * 7);
        if *byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }

    None
}

fn validate_geo_site_body(body: &[u8]) -> Result<(), String> {
    let mut domains = 0usize;
    let mut attributes = 0usize;
    visit_length_delimited_fields(body, |field, value| {
        match field {
            1 if value.len() > MAX_GEODATA_CODE_SIZE => {
                return Err(format!(
                    "geodata code is {} bytes; maximum supported size is {MAX_GEODATA_CODE_SIZE} bytes",
                    value.len()
                ));
            }
            2 => {
                domains = domains.saturating_add(1);
                if domains > MAX_GEODATA_DOMAINS {
                    return Err(format!(
                        "geosite contains more than {MAX_GEODATA_DOMAINS} domains"
                    ));
                }
                validate_geo_domain_body(value, &mut attributes)?;
            }
            _ => {}
        }
        Ok(())
    })
}

fn validate_geo_domain_body(body: &[u8], total_attributes: &mut usize) -> Result<(), String> {
    visit_length_delimited_fields(body, |field, value| {
        match field {
            2 if value.len() > MAX_GEODATA_DOMAIN_VALUE_SIZE => {
                return Err(format!(
                    "geosite domain is {} bytes; maximum supported size is {MAX_GEODATA_DOMAIN_VALUE_SIZE} bytes",
                    value.len()
                ));
            }
            3 => {
                *total_attributes = total_attributes.saturating_add(1);
                if *total_attributes > MAX_GEODATA_DOMAIN_ATTRIBUTES {
                    return Err(format!(
                        "geosite contains more than {MAX_GEODATA_DOMAIN_ATTRIBUTES} domain attributes"
                    ));
                }
                if value.len() > MAX_GEODATA_ATTRIBUTE_SIZE {
                    return Err(format!(
                        "geosite domain attribute is {} bytes; maximum supported size is {MAX_GEODATA_ATTRIBUTE_SIZE} bytes",
                        value.len()
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn validate_geo_ip_body(body: &[u8]) -> Result<(), String> {
    let mut cidrs = 0usize;
    visit_length_delimited_fields(body, |field, value| {
        match field {
            1 if value.len() > MAX_GEODATA_CODE_SIZE => {
                return Err(format!(
                    "geodata code is {} bytes; maximum supported size is {MAX_GEODATA_CODE_SIZE} bytes",
                    value.len()
                ));
            }
            2 => {
                cidrs = cidrs.saturating_add(1);
                if cidrs > MAX_GEODATA_CIDRS {
                    return Err(format!(
                        "geoip contains more than {MAX_GEODATA_CIDRS} CIDRs"
                    ));
                }
                if value.len() > MAX_GEODATA_CIDR_SIZE {
                    return Err(format!(
                        "geoip CIDR record is {} bytes; maximum supported size is {MAX_GEODATA_CIDR_SIZE} bytes",
                        value.len()
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn visit_length_delimited_fields(
    message: &[u8],
    mut visitor: impl FnMut(u32, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let mut offset = 0usize;
    while offset < message.len() {
        let (key, key_len) = decode_varint_from_slice(&message[offset..])
            .ok_or_else(|| "invalid protobuf field key".to_owned())?;
        offset = offset
            .checked_add(key_len)
            .ok_or_else(|| "protobuf field offset overflow".to_owned())?;
        let field = u32::try_from(key >> 3)
            .map_err(|_| "protobuf field number does not fit in u32".to_owned())?;
        if field == 0 {
            return Err("protobuf field number cannot be zero".to_owned());
        }

        match key & 0x07 {
            0 => {
                let (_, value_len) = decode_varint_from_slice(&message[offset..])
                    .ok_or_else(|| "invalid protobuf varint field".to_owned())?;
                offset = offset
                    .checked_add(value_len)
                    .ok_or_else(|| "protobuf varint offset overflow".to_owned())?;
            }
            1 => {
                offset = offset
                    .checked_add(8)
                    .filter(|end| *end <= message.len())
                    .ok_or_else(|| "truncated protobuf fixed64 field".to_owned())?;
            }
            2 => {
                let (value_len, prefix_len) = decode_varint_from_slice(&message[offset..])
                    .ok_or_else(|| "invalid protobuf length-delimited field".to_owned())?;
                let value_len = usize::try_from(value_len)
                    .map_err(|_| "protobuf field length does not fit in usize".to_owned())?;
                let value_start = offset
                    .checked_add(prefix_len)
                    .ok_or_else(|| "protobuf field offset overflow".to_owned())?;
                let value_end = value_start
                    .checked_add(value_len)
                    .filter(|end| *end <= message.len())
                    .ok_or_else(|| "truncated protobuf length-delimited field".to_owned())?;
                visitor(field, &message[value_start..value_end])?;
                offset = value_end;
            }
            5 => {
                offset = offset
                    .checked_add(4)
                    .filter(|end| *end <= message.len())
                    .ok_or_else(|| "truncated protobuf fixed32 field".to_owned())?;
            }
            wire_type => {
                return Err(format!("unsupported protobuf wire type {wire_type}"));
            }
        }
    }

    Ok(())
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
    use std::{
        fs,
        io::{self, BufReader, Cursor, Read, Seek, SeekFrom},
        path::PathBuf,
        sync::Arc,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use prost::Message;

    use super::{
        find_entry_body, scan_entry_code, validate_geo_site_body, GeoCidr, GeoDomain,
        GeoDomainAttribute, GeoIp, GeoSite, GeodataCacheKey, GeodataError, GeodataLoader,
        MAX_GEODATA_DOMAINS, MAX_GEODATA_ENTRY_SIZE, MAX_GEODATA_FILE_SIZE,
        MAX_GEODATA_INDEX_ENTRIES,
    };

    struct CountingReader {
        inner: Cursor<Vec<u8>>,
        reads: usize,
        seeks: usize,
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                reads: 0,
                seeks: 0,
            }
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            self.inner.read(output)
        }
    }

    impl Seek for CountingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.seeks += 1;
            self.inner.seek(position)
        }
    }

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

    #[test]
    fn geodata_loader_rejects_absolute_and_parent_paths() {
        let root = unique_temp_dir("confined-paths");
        let loader = GeodataLoader::from_dirs(vec![root.clone()]);

        let parent_error = loader.open_file("../outside.dat").unwrap_err();
        assert!(matches!(parent_error, GeodataError::InvalidPath { .. }));

        let absolute_error = loader
            .open_file(root.join("absolute.dat").to_str().unwrap())
            .unwrap_err();
        assert!(matches!(absolute_error, GeodataError::InvalidPath { .. }));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn geodata_loader_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("symlink-escape");
        let geodata_dir = root.join("assets");
        fs::create_dir(&geodata_dir).unwrap();
        let outside = root.join("outside.dat");
        fs::write(&outside, [0_u8]).unwrap();
        symlink(&outside, geodata_dir.join("escaped.dat")).unwrap();

        let loader = GeodataLoader::from_dirs(vec![geodata_dir]);
        let error = loader.open_file("escaped.dat").unwrap_err();

        assert!(matches!(error, GeodataError::InvalidPath { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn geodata_loader_rejects_intermediate_symlink_components() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("symlink-component");
        let real_dir = root.join("real");
        fs::create_dir(&real_dir).unwrap();
        fs::write(real_dir.join("geo.dat"), [0_u8]).unwrap();
        symlink(&real_dir, root.join("linked")).unwrap();

        let loader = GeodataLoader::from_dirs(vec![root.clone()]);
        let error = loader.open_file("linked/geo.dat").unwrap_err();

        assert!(matches!(error, GeodataError::InvalidPath { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn geodata_loader_rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = unique_temp_dir("fifo");
        let fifo = root.join("geo.dat");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_path` is a live NUL-terminated filesystem path.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let loader = GeodataLoader::from_dirs(vec![root.clone()]);

        let started = Instant::now();
        let error = loader.open_file("geo.dat").unwrap_err();

        assert!(matches!(error, GeodataError::FileNotFound { .. }));
        assert!(started.elapsed().as_secs() < 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn geodata_reader_rejects_oversized_entry_before_allocation() {
        let root = unique_temp_dir("oversized-entry");
        let path = root.join("entry.dat");
        let mut bytes = vec![0];
        encode_varint((MAX_GEODATA_ENTRY_SIZE as u64) + 1, &mut bytes);
        fs::write(&path, bytes).unwrap();

        let error = find_entry_body(fs::File::open(&path).unwrap(), &path, "TEST").unwrap_err();

        assert!(matches!(error, GeodataError::InvalidFile { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn geodata_reader_rejects_oversized_file() {
        let root = unique_temp_dir("oversized-file");
        let path = root.join("large.dat");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_GEODATA_FILE_SIZE + 1).unwrap();

        let error = find_entry_body(fs::File::open(&path).unwrap(), &path, "TEST").unwrap_err();

        assert!(matches!(error, GeodataError::InvalidFile { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn geodata_reader_bounds_index_entry_count() {
        let root = unique_temp_dir("oversized-index");
        let path = root.join("many.dat");
        let mut bytes = Vec::new();
        for index in 0..=MAX_GEODATA_INDEX_ENTRIES {
            let code = format!("C{index:05X}");
            let mut body = vec![0x0a, code.len() as u8];
            body.extend_from_slice(code.as_bytes());
            bytes.push(0);
            encode_varint(body.len() as u64, &mut bytes);
            bytes.extend_from_slice(&body);
        }
        fs::write(&path, bytes).unwrap();

        let error = find_entry_body(fs::File::open(&path).unwrap(), &path, "MISSING").unwrap_err();

        assert!(matches!(error, GeodataError::InvalidFile { .. }));
        assert!(error.to_string().contains("entries"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_code_length_overflow_is_rejected_without_panicking() {
        let mut body = vec![0x0a];
        encode_varint(u64::MAX, &mut body);
        let root = unique_temp_dir("overflow-code");
        let path = root.join("overflow.dat");
        write_entry_file(&path, &[body]);

        let error = find_entry_body(fs::File::open(&path).unwrap(), &path, "TEST").unwrap_err();

        assert!(matches!(error, GeodataError::InvalidFile { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn index_finds_code_after_another_protobuf_field() {
        let root = unique_temp_dir("reordered-code");
        let path = root.join("reordered.dat");
        let body = vec![0x12, 0x00, 0x0a, 0x04, b'T', b'E', b'S', b'T'];
        write_entry_file(&path, std::slice::from_ref(&body));

        let found = find_entry_body(fs::File::open(&path).unwrap(), &path, "TEST")
            .unwrap()
            .unwrap();

        assert_eq!(found, body);
        assert_eq!(GeoSite::decode(found.as_slice()).unwrap().code, "TEST");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_code_fields_use_last_value_like_protobuf_decode() {
        let root = unique_temp_dir("duplicate-code");
        let path = root.join("duplicate.dat");
        let body = vec![0x0a, 0x01, b'A', 0x0a, 0x01, b'B'];
        write_entry_file(&path, std::slice::from_ref(&body));

        assert!(find_entry_body(fs::File::open(&path).unwrap(), &path, "A")
            .unwrap()
            .is_none());
        let found = find_entry_body(fs::File::open(&path).unwrap(), &path, "B")
            .unwrap()
            .unwrap();
        assert_eq!(GeoSite::decode(found.as_slice()).unwrap().code, "B");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn code_scan_skips_many_fields_without_underlying_seeks() {
        let mut body = Vec::new();
        for _ in 0..4_096 {
            body.extend_from_slice(&[0x12, 0x00]);
        }
        body.extend_from_slice(&[0x0a, 0x04, b'T', b'E', b'S', b'T']);
        let body_len = body.len();
        let mut reader = BufReader::with_capacity(64, CountingReader::new(body));

        let code =
            scan_entry_code(&mut reader, body_len, PathBuf::from("memory.dat").as_path()).unwrap();
        let counts = reader.into_inner();

        assert_eq!(code.as_deref(), Some("TEST"));
        assert_eq!(
            counts.seeks, 0,
            "field skipping must consume the buffered stream rather than seek once per field"
        );
        assert!(
            counts.reads < 200,
            "buffered scanning should read in blocks, got {} reads",
            counts.reads
        );
    }

    #[test]
    fn geosite_record_count_is_bounded_before_decode() {
        let mut body = vec![0x0a, 0x04];
        body.extend_from_slice(b"TEST");
        for _ in 0..=MAX_GEODATA_DOMAINS {
            body.extend_from_slice(&[0x12, 0x00]);
        }

        let error = validate_geo_site_body(&body).unwrap_err();

        assert!(error.contains("domains"));
    }

    #[test]
    fn decoded_geodata_cache_reuses_arc_allocations() {
        let key = GeodataCacheKey::new("geosite.dat", "TEST");
        let cached = Arc::new(GeoSite {
            code: "TEST".to_owned(),
            domain: Vec::new(),
        });
        let mut loader = GeodataLoader::from_dirs(Vec::new());
        loader.sites.insert(key, Arc::clone(&cached));

        let loaded = loader.load_site("geosite.dat", "TEST").unwrap();

        assert!(Arc::ptr_eq(&cached, &loaded));
    }

    #[test]
    fn cached_geosite_over_budget_is_rejected_before_rebuilding_matchers() {
        let key = GeodataCacheKey::new("geosite.dat", "TEST");
        let cached = Arc::new(GeoSite {
            code: "TEST".to_owned(),
            domain: (0..3)
                .map(|index| GeoDomain {
                    r#type: 2,
                    value: format!("{index}.example"),
                    attribute: Vec::new(),
                })
                .collect(),
        });
        let mut loader = GeodataLoader::from_dirs(Vec::new());
        loader.sites.insert(key, cached);

        let first = loader
            .load_site_matchers("geosite.dat", "TEST", &[], 3)
            .unwrap();
        let error = loader
            .load_site_matchers("geosite.dat", "TEST", &[], 2)
            .unwrap_err();

        assert_eq!(first.len(), 3);
        assert!(matches!(
            error,
            GeodataError::DomainMatcherBudgetExceeded {
                expanded: 3,
                remaining: 2,
                ..
            }
        ));
        assert_eq!(
            loader.domain_matcher_builds, 3,
            "the rejected cached reference must not clone or compile any matcher"
        );
    }

    #[test]
    fn repeated_geosite_attribute_selection_reuses_one_domain_scan() {
        let key = GeodataCacheKey::new("geosite.dat", "TEST");
        let cached = Arc::new(GeoSite {
            code: "TEST".to_owned(),
            domain: (0..3)
                .map(|index| GeoDomain {
                    r#type: 2,
                    value: format!("{index}.example"),
                    attribute: vec![GeoDomainAttribute {
                        key: "ads".to_owned(),
                    }],
                })
                .collect(),
        });
        let mut loader = GeodataLoader::from_dirs(Vec::new());
        loader.sites.insert(key, cached);
        let attrs = vec!["ads".to_owned()];

        loader
            .load_site_matchers("geosite.dat", "TEST", &attrs, 3)
            .unwrap();
        loader
            .load_site_matchers("geosite.dat", "TEST", &attrs, 3)
            .unwrap();
        let error = loader
            .load_site_matchers("geosite.dat", "TEST", &attrs, 2)
            .unwrap_err();

        assert!(matches!(
            error,
            GeodataError::DomainMatcherBudgetExceeded {
                expanded: 3,
                remaining: 2,
                ..
            }
        ));
        assert_eq!(
            loader.domain_filter_scans, 3,
            "repeated references to the same canonical attribute set must reuse the selection"
        );
        assert_eq!(
            loader.domain_matcher_builds, 6,
            "the over-budget reference must fail before rebuilding matchers"
        );
    }

    #[test]
    fn cached_geoip_over_budget_is_rejected_before_rebuilding_matchers() {
        let key = GeodataCacheKey::new("geoip.dat", "TEST");
        let cached = Arc::new(GeoIp {
            code: "TEST".to_owned(),
            cidr: vec![
                GeoCidr {
                    ip: vec![192, 0, 2, 0],
                    prefix: 24,
                },
                GeoCidr {
                    ip: vec![198, 51, 100, 0],
                    prefix: 24,
                },
            ],
            reverse_match: false,
        });
        let mut loader = GeodataLoader::from_dirs(Vec::new());
        loader.ips.insert(key, cached);

        let first = loader
            .load_ip_matchers("geoip.dat", "TEST", false, 2)
            .unwrap();
        let error = loader
            .load_ip_matchers("geoip.dat", "TEST", false, 1)
            .unwrap_err();

        assert_eq!(first.len(), 2);
        assert!(matches!(
            error,
            GeodataError::IpMatcherBudgetExceeded {
                expanded: 2,
                remaining: 1,
                ..
            }
        ));
        assert_eq!(
            loader.ip_matcher_builds, 2,
            "the rejected cached reference must not rebuild any matcher"
        );
    }

    #[test]
    fn multiple_codes_share_one_pinned_file_index() {
        let root = unique_temp_dir("shared-index");
        let path = root.join("geosite.dat");
        let first = GeoSite {
            code: "FIRST".to_owned(),
            domain: Vec::new(),
        }
        .encode_to_vec();
        let second = GeoSite {
            code: "SECOND".to_owned(),
            domain: Vec::new(),
        }
        .encode_to_vec();
        let mut bytes = Vec::new();
        for body in [&first, &second] {
            bytes.push(0);
            encode_varint(body.len() as u64, &mut bytes);
            bytes.extend_from_slice(body);
        }
        fs::write(path, bytes).unwrap();
        let mut loader = GeodataLoader::from_dirs(vec![root.clone()]);

        assert_eq!(
            loader.load_site("geosite.dat", "FIRST").unwrap().code,
            "FIRST"
        );
        assert_eq!(
            loader.load_site("geosite.dat", "SECOND").unwrap().code,
            "SECOND"
        );
        assert_eq!(loader.index_builds, 1);

        fs::remove_dir_all(root).unwrap();
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "xray-config-geodata-{label}-{}-{timestamp}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
        while value >= 0x80 {
            output.push(value as u8 | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    fn write_entry_file(path: &std::path::Path, bodies: &[Vec<u8>]) {
        let mut bytes = Vec::new();
        for body in bodies {
            bytes.push(0);
            encode_varint(body.len() as u64, &mut bytes);
            bytes.extend_from_slice(body);
        }
        fs::write(path, bytes).unwrap();
    }
}
