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
use xray_routing::{
    DomainNameMode, DomainPatternSet, DomainPatternSetBuilder, IpMatcherSetBuilder,
    IpRangeSetBuilder,
};

use crate::geodata_cache::{FileIdentity, GeoIpEntry, GeodataCache, IpKey, SiteKey};
use crate::geodata_wire::{self, Unsupported};
use crate::model::domain_matcher_set_error;
use crate::{ConfigModelError, DomainMatcher, IpCidr, RegexMatcher};

const MAX_GEODATA_FILE_SIZE: u64 = 128 * 1024 * 1024;
const MAX_GEODATA_ENTRY_SIZE: usize = 32 * 1024 * 1024;
const MAX_GEODATA_INDEX_ENTRIES: usize = 65_536;
const MAX_GEODATA_INDEX_CODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_GEODATA_CODE_SIZE: usize = 256;
const MAX_GEODATA_DOMAINS: usize = 200_000;
const MAX_GEODATA_DOMAIN_ATTRIBUTES: usize = 400_000;
const MAX_GEODATA_DOMAIN_VALUE_SIZE: usize = 4 * 1024;
const MAX_GEODATA_ATTRIBUTE_SIZE: usize = 1024;
const MAX_GEODATA_CIDRS: usize = 500_000;
const MAX_GEODATA_CIDR_SIZE: usize = 128;

/// Resolves geodata references for one configuration.
///
/// Compiled categories come from the process-wide [`GeodataCache`] when the
/// same version of the file was compiled before; otherwise the entry is read,
/// decoded without copying its names, compiled into packed matchers and
/// cached. Files stay open for the loader's lifetime, so every lookup of one
/// configuration sees the same file version.
#[derive(Debug)]
pub(crate) struct GeodataLoader {
    search_dirs: Vec<PathBuf>,
    files: HashMap<String, OpenedGeodataFile>,
    cache: Arc<GeodataCache>,
    #[cfg(test)]
    index_builds: usize,
    #[cfg(test)]
    site_decodes: usize,
    #[cfg(test)]
    ip_decodes: usize,
}

impl Default for GeodataLoader {
    fn default() -> Self {
        Self::from_dirs(default_geodata_dirs())
    }
}

impl GeodataLoader {
    pub(crate) fn from_dirs(search_dirs: Vec<PathBuf>) -> Self {
        Self::with_cache(search_dirs, Arc::clone(GeodataCache::global()))
    }

    pub(crate) fn with_cache(search_dirs: Vec<PathBuf>, cache: Arc<GeodataCache>) -> Self {
        Self {
            search_dirs,
            files: HashMap::new(),
            cache,
            #[cfg(test)]
            index_builds: 0,
            #[cfg(test)]
            site_decodes: 0,
            #[cfg(test)]
            ip_decodes: 0,
        }
    }

    /// The domains `file_name:code@attrs` selects, compiled for `mode` into
    /// one shared set. Its [`DomainPatternSet::source_count`] is what the
    /// selection charges against the matcher budget.
    pub(crate) fn load_site_patterns(
        &mut self,
        file_name: &str,
        code: &str,
        attrs: &[String],
        mode: DomainNameMode,
        max_matchers: usize,
    ) -> Result<Arc<DomainPatternSet>, GeodataError> {
        let code = normalize_code(code);
        let identity = self.opened_file(file_name)?.identity.clone();
        let key = SiteKey::new(identity, &code, attrs, mode);
        if let Some(patterns) = self.cache.site(&key) {
            ensure_domain_matcher_budget(file_name, &code, patterns.source_count(), max_matchers)?;
            return Ok(patterns);
        }

        let (body, path) = self.read_entry(file_name, &code, validate_geo_site_body)?;
        self.record_site_decode();
        let site = DecodedSite::decode(&body, &path, &code)?;
        let selection = site.selection(key.attrs(), &path)?;
        ensure_domain_matcher_budget(file_name, &code, selection.count, max_matchers)?;

        let mut builder = DomainPatternSet::builder();
        selection.reserve(&mut builder);
        let mut dotted = false;
        site.for_each_selected(key.attrs(), &path, |domain| {
            dotted |= domain.insert_into(&mut builder, mode, file_name, &code)?;
            Ok(())
        })?;
        // The names are copied into the builder: free the entry before the
        // tables are built.
        drop(site);
        drop(body);
        let patterns = builder
            .build()
            .map_err(|error| GeodataError::InvalidDomainMatcher {
                file_name: file_name.to_owned(),
                code: code.clone(),
                source: domain_matcher_set_error(error),
            })?;
        let patterns = Arc::new(patterns);
        if !self.opened_file(file_name)?.unchanged()? {
            return Ok(patterns);
        }
        let key = if dotted { key } else { key.mode_independent() };
        Ok(self.cache.insert_site(key, patterns))
    }

    /// The domains `file_name:code@attrs` selects, one matcher each, for the
    /// rules that need them apart, such as `dns.hosts`. Not cached.
    pub(crate) fn load_site_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        attrs: &[String],
        max_matchers: usize,
    ) -> Result<Vec<DomainMatcher>, GeodataError> {
        let code = normalize_code(code);
        let (body, path) = self.read_entry(file_name, &code, validate_geo_site_body)?;
        self.record_site_decode();
        let site = DecodedSite::decode(&body, &path, &code)?;
        let selection = site.selection(attrs, &path)?;
        ensure_domain_matcher_budget(file_name, &code, selection.count, max_matchers)?;

        let mut matchers = Vec::with_capacity(selection.count);
        site.for_each_selected(attrs, &path, |domain| {
            matchers.push(domain.to_matcher(file_name, &code)?);
            Ok(())
        })?;
        Ok(matchers)
    }

    fn record_site_decode(&mut self) {
        #[cfg(test)]
        {
            self.site_decodes += 1;
        }
    }

    /// Inserts the routing IP rules of `file_name:code` into `matchers` and
    /// returns how many were inserted.
    pub(crate) fn load_ip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        max_matchers: usize,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Result<usize, GeodataError> {
        self.load_ip_matchers_with_asset_reverse(
            file_name,
            code,
            inverse,
            max_matchers,
            true,
            matchers,
        )
    }

    /// Loads Xray DNS IP rules without the legacy asset-level `reverse_match` flag.
    pub(crate) fn load_dns_ip_matchers(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        max_matchers: usize,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Result<usize, GeodataError> {
        self.load_ip_matchers_with_asset_reverse(
            file_name,
            code,
            inverse,
            max_matchers,
            false,
            matchers,
        )
    }

    fn load_ip_matchers_with_asset_reverse(
        &mut self,
        file_name: &str,
        code: &str,
        inverse: bool,
        max_matchers: usize,
        apply_asset_reverse: bool,
        matchers: &mut IpMatcherSetBuilder,
    ) -> Result<usize, GeodataError> {
        let code = normalize_code(code);
        let geoip = self.load_geoip(file_name, &code, max_matchers)?;
        let inverse = inverse ^ (apply_asset_reverse && geoip.reverse_match);
        matchers.insert_geoip_set(&geoip.ranges, geoip.cidr_count, inverse);
        Ok(geoip.cidr_count)
    }

    fn load_geoip(
        &mut self,
        file_name: &str,
        code: &str,
        max_matchers: usize,
    ) -> Result<GeoIpEntry, GeodataError> {
        let identity = self.opened_file(file_name)?.identity.clone();
        let key = IpKey::new(identity, code);
        if let Some(geoip) = self.cache.ip(&key) {
            ensure_ip_matcher_budget(file_name, code, geoip.cidr_count, max_matchers)?;
            return Ok(geoip);
        }

        let (body, path) = self.read_entry(file_name, code, validate_geo_ip_body)?;
        #[cfg(test)]
        {
            self.ip_decodes += 1;
        }
        let geoip = DecodedGeoIp::decode(&body, &path, code)?;
        let (mut ipv4, mut ipv6) = (0, 0);
        geoip.for_each_cidr(&path, |ip, _| {
            if ip.len() == 16 {
                ipv6 += 1;
            } else {
                ipv4 += 1;
            }
            Ok(())
        })?;
        let cidr_count = ipv4 + ipv6;
        ensure_ip_matcher_budget(file_name, code, cidr_count, max_matchers)?;

        let mut ranges = IpRangeSetBuilder::with_capacity(ipv4, ipv6);
        geoip.for_each_cidr(&path, |ip, prefix| {
            ranges.insert_cidr(cidr_to_ip_cidr(ip, prefix, file_name, code)?.cidr());
            Ok(())
        })?;
        let geoip = GeoIpEntry {
            ranges: ranges.build(),
            cidr_count,
            reverse_match: geoip.reverse_match(),
        };
        drop(body);
        if !self.opened_file(file_name)?.unchanged()? {
            return Ok(geoip);
        }
        Ok(self.cache.insert_ip(key, geoip))
    }

    /// Checks that `file_name` holds `code`, as Xray-core's `checkFile` does
    /// for a rule it only validates: the file is indexed, but no entry is
    /// decoded and no matcher is built.
    pub(crate) fn check_code(&mut self, file_name: &str, code: &str) -> Result<(), GeodataError> {
        let code = normalize_code(code);
        if self.indexed_file(file_name)?.contains(&code) {
            return Ok(());
        }
        Err(GeodataError::CodeNotFound {
            file_name: file_name.to_owned(),
            code,
        })
    }

    /// Reads and bounds-checks the entry body of `code`.
    fn read_entry(
        &mut self,
        file_name: &str,
        code: &str,
        validate_body: fn(&[u8]) -> Result<(), String>,
    ) -> Result<(Vec<u8>, PathBuf), GeodataError> {
        let indexed = self.indexed_file(file_name)?;
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
        Ok((body, path))
    }

    fn opened_file(&mut self, file_name: &str) -> Result<&mut OpenedGeodataFile, GeodataError> {
        if !self.files.contains_key(file_name) {
            let (file, path) = self.open_file(file_name)?;
            let opened = OpenedGeodataFile::new(file, path)?;
            self.files.insert(file_name.to_owned(), opened);
        }
        Ok(self
            .files
            .get_mut(file_name)
            .expect("geodata file was inserted above"))
    }

    fn indexed_file(&mut self, file_name: &str) -> Result<&mut OpenedGeodataFile, GeodataError> {
        #[cfg(test)]
        let built = self
            .files
            .get(file_name)
            .is_none_or(|file| file.entries.is_none());
        self.opened_file(file_name)?.index()?;
        #[cfg(test)]
        if built {
            self.index_builds += 1;
        }
        self.opened_file(file_name)
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

/// A geodata file opened for one configuration, its identity taken from the
/// open descriptor and its code index built on first use.
#[derive(Debug)]
struct OpenedGeodataFile {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
    entries: Option<HashMap<String, GeodataEntryLocation>>,
}

impl OpenedGeodataFile {
    fn new(file: File, path: PathBuf) -> Result<Self, GeodataError> {
        let metadata = file.metadata().map_err(|source| GeodataError::Read {
            path: path.clone(),
            source,
        })?;
        let identity = FileIdentity::new(&path, &metadata);
        Ok(Self {
            file,
            path,
            identity,
            entries: None,
        })
    }

    fn index(&mut self) -> Result<&HashMap<String, GeodataEntryLocation>, GeodataError> {
        if self.entries.is_none() {
            self.entries = Some(index_geodata_file(&self.file, &self.path)?);
        }
        Ok(self.entries.as_ref().expect("index was built above"))
    }

    fn contains(&self, code: &str) -> bool {
        self.entries
            .as_ref()
            .is_some_and(|entries| entries.contains_key(code))
    }

    /// Whether the file still has the identity it was opened with, so what
    /// was read from it may be cached under that identity.
    fn unchanged(&self) -> Result<bool, GeodataError> {
        let metadata = self.file.metadata().map_err(|source| GeodataError::Read {
            path: self.path.clone(),
            source,
        })?;
        Ok(FileIdentity::new(&self.path, &metadata) == self.identity)
    }

    fn read_entry(&mut self, code: &str) -> Result<Option<Vec<u8>>, GeodataError> {
        let Some(location) = self.index()?.get(code).copied() else {
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
    OpenedGeodataFile::new(file, path.to_path_buf())?.read_entry(code)
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

fn ensure_domain_matcher_budget(
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

fn ensure_ip_matcher_budget(
    file_name: &str,
    code: &str,
    matcher_count: usize,
    max_matchers: usize,
) -> Result<(), GeodataError> {
    if matcher_count > max_matchers {
        return Err(GeodataError::IpMatcherBudgetExceeded {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
            expanded: matcher_count,
            remaining: max_matchers,
        });
    }
    Ok(())
}

fn check_decoded_code(decoded: &str, code: &str, path: &Path) -> Result<(), GeodataError> {
    if decoded != code {
        return Err(GeodataError::InvalidFile {
            path: path.to_path_buf(),
            message: "decoded geodata code does not match its index entry".to_owned(),
        });
    }
    Ok(())
}

/// A second walk over a body the first walk accepted cannot fail; this is the
/// error it would report if it did.
fn reread_error(path: &Path) -> GeodataError {
    invalid_geodata_file(path, "geodata entry changed between two reads")
}

/// A `GeoSite` entry, read in place when the body is plain protobuf
/// ([`geodata_wire`]) and decoded by prost otherwise.
enum DecodedSite<'a> {
    Wire(&'a [u8]),
    Prost(GeoSite),
}

impl<'a> DecodedSite<'a> {
    fn decode(body: &'a [u8], path: &Path, code: &str) -> Result<Self, GeodataError> {
        match geodata_wire::site_code(body) {
            Ok(decoded) => {
                check_decoded_code(decoded, code, path)?;
                Ok(Self::Wire(body))
            }
            Err(Unsupported) => {
                let site = GeoSite::decode(body).map_err(|source| GeodataError::Decode {
                    path: path.to_path_buf(),
                    source,
                })?;
                check_decoded_code(&site.code, code, path)?;
                Ok(Self::Prost(site))
            }
        }
    }

    /// Visits the domains every attribute filter of `attrs` selects, in
    /// entry order.
    fn for_each_selected(
        &self,
        attrs: &[String],
        path: &Path,
        mut visit: impl FnMut(&DomainRecord<'_>) -> Result<(), GeodataError>,
    ) -> Result<(), GeodataError> {
        let mut visit = |domain: &DomainRecord<'_>| {
            if domain.has_attrs(attrs) {
                visit(domain)
            } else {
                Ok(())
            }
        };
        match self {
            Self::Wire(body) => {
                for domain in geodata_wire::site_domains(body) {
                    let domain = domain.map_err(|Unsupported| reread_error(path))?;
                    visit(&DomainRecord::Wire(domain))?;
                }
            }
            Self::Prost(site) => {
                for domain in &site.domain {
                    visit(&DomainRecord::Prost(domain))?;
                }
            }
        }
        Ok(())
    }

    fn selection(&self, attrs: &[String], path: &Path) -> Result<SiteSelection, GeodataError> {
        let mut selection = SiteSelection::default();
        self.for_each_selected(attrs, path, |domain| {
            selection.add(domain);
            Ok(())
        })?;
        Ok(selection)
    }
}

/// How many domains of each kind a selection holds, and their bytes.
#[derive(Debug, Default)]
struct SiteSelection {
    count: usize,
    full: (usize, usize),
    suffix: (usize, usize),
    keyword: (usize, usize),
    regex: usize,
}

impl SiteSelection {
    fn add(&mut self, domain: &DomainRecord<'_>) {
        self.count += 1;
        let len = domain.value().len();
        let kind = match GeoDomainType::try_from(domain.kind()) {
            Ok(GeoDomainType::Full) => &mut self.full,
            Ok(GeoDomainType::Domain) => &mut self.suffix,
            Ok(GeoDomainType::Substr) => &mut self.keyword,
            Ok(GeoDomainType::Regex) => {
                self.regex += 1;
                return;
            }
            Err(_) => return,
        };
        kind.0 += 1;
        kind.1 += len;
    }

    fn reserve(&self, builder: &mut DomainPatternSetBuilder) {
        builder.reserve_full(self.full.0, self.full.1);
        builder.reserve_suffix(self.suffix.0, self.suffix.1);
        builder.reserve_keyword(self.keyword.0, self.keyword.1);
        builder.reserve_regex(self.regex);
    }
}

/// One domain of a [`DecodedSite`].
enum DomainRecord<'a> {
    Wire(geodata_wire::Domain<'a>),
    Prost(&'a GeoDomain),
}

impl DomainRecord<'_> {
    fn kind(&self) -> i32 {
        match self {
            Self::Wire(domain) => domain.kind,
            Self::Prost(domain) => domain.r#type,
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::Wire(domain) => domain.value,
            Self::Prost(domain) => &domain.value,
        }
    }

    /// Whether the domain carries every attribute of `attrs`, compared ASCII
    /// case-insensitively.
    fn has_attrs(&self, attrs: &[String]) -> bool {
        attrs.iter().all(|attr| match self {
            Self::Wire(domain) => domain
                .attribute_keys()
                .any(|key| key.eq_ignore_ascii_case(attr)),
            Self::Prost(domain) => domain
                .attribute
                .iter()
                .any(|candidate| candidate.key.eq_ignore_ascii_case(attr)),
        })
    }

    fn checked_kind(&self, file_name: &str, code: &str) -> Result<GeoDomainType, GeodataError> {
        if self.value().is_empty() {
            return Err(GeodataError::InvalidDomain {
                file_name: file_name.to_owned(),
                code: code.to_owned(),
                message: "domain value cannot be empty".to_owned(),
            });
        }
        GeoDomainType::try_from(self.kind()).map_err(|_| GeodataError::UnsupportedDomainType {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
            domain_type: self.kind(),
        })
    }

    fn regex(&self, file_name: &str, code: &str) -> Result<RegexMatcher, GeodataError> {
        RegexMatcher::new(self.value()).map_err(|source| GeodataError::InvalidDomainMatcher {
            file_name: file_name.to_owned(),
            code: code.to_owned(),
            source: source.into(),
        })
    }

    fn to_matcher(&self, file_name: &str, code: &str) -> Result<DomainMatcher, GeodataError> {
        let value = self.value().to_owned();
        Ok(match self.checked_kind(file_name, code)? {
            GeoDomainType::Substr => DomainMatcher::Keyword(value),
            GeoDomainType::Regex => DomainMatcher::Regex(self.regex(file_name, code)?),
            GeoDomainType::Domain => DomainMatcher::Suffix(value),
            GeoDomainType::Full => DomainMatcher::Full(value),
        })
    }

    /// Adds the domain to `builder` as [`Self::to_matcher`]'s matcher would
    /// be added, and returns whether it is a `full:` or `domain:` name with
    /// a trailing dot, which the two name modes compile differently.
    fn insert_into(
        &self,
        builder: &mut DomainPatternSetBuilder,
        mode: DomainNameMode,
        file_name: &str,
        code: &str,
    ) -> Result<bool, GeodataError> {
        let value = self.value();
        match self.checked_kind(file_name, code)? {
            GeoDomainType::Substr => builder.insert_keyword(value),
            GeoDomainType::Regex => builder.insert_regex(&self.regex(file_name, code)?),
            GeoDomainType::Domain => {
                builder.insert_suffix(value, mode);
                return Ok(value.ends_with('.'));
            }
            GeoDomainType::Full => {
                builder.insert_full(value, mode);
                return Ok(value.ends_with('.'));
            }
        }
        Ok(false)
    }
}

/// A `GeoIP` entry, read in place when the body is plain protobuf and
/// decoded by prost otherwise.
enum DecodedGeoIp<'a> {
    Wire { body: &'a [u8], reverse_match: bool },
    Prost(GeoIp),
}

impl<'a> DecodedGeoIp<'a> {
    fn decode(body: &'a [u8], path: &Path, code: &str) -> Result<Self, GeodataError> {
        match geodata_wire::geoip_header(body) {
            Ok(header) => {
                check_decoded_code(header.code, code, path)?;
                Ok(Self::Wire {
                    body,
                    reverse_match: header.reverse_match,
                })
            }
            Err(Unsupported) => {
                let geoip = GeoIp::decode(body).map_err(|source| GeodataError::Decode {
                    path: path.to_path_buf(),
                    source,
                })?;
                check_decoded_code(&geoip.code, code, path)?;
                Ok(Self::Prost(geoip))
            }
        }
    }

    fn reverse_match(&self) -> bool {
        match self {
            Self::Wire { reverse_match, .. } => *reverse_match,
            Self::Prost(geoip) => geoip.reverse_match,
        }
    }

    /// Visits every CIDR's IP bytes and prefix, in entry order.
    fn for_each_cidr(
        &self,
        path: &Path,
        mut visit: impl FnMut(&[u8], u32) -> Result<(), GeodataError>,
    ) -> Result<(), GeodataError> {
        match self {
            Self::Wire { body, .. } => {
                for cidr in geodata_wire::geoip_cidrs(body) {
                    let cidr = cidr.map_err(|Unsupported| reread_error(path))?;
                    visit(cidr.ip, cidr.prefix)?;
                }
            }
            Self::Prost(geoip) => {
                for cidr in &geoip.cidr {
                    visit(&cidr.ip, cidr.prefix)?;
                }
            }
        }
        Ok(())
    }
}

fn cidr_to_ip_cidr(
    ip: &[u8],
    prefix: u32,
    file_name: &str,
    code: &str,
) -> Result<IpCidr, GeodataError> {
    let ip = match ip {
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
                message: format!("IP byte slice must be 4 or 16 bytes, got {}", ip.len()),
            });
        }
    };

    let prefix = u8::try_from(prefix).map_err(|_| GeodataError::InvalidCidr {
        file_name: file_name.to_owned(),
        code: code.to_owned(),
        message: format!("CIDR prefix length {prefix} does not fit in u8"),
    })?;

    IpCidr::new(ip, prefix).map_err(|source| GeodataError::InvalidCidr {
        file_name: file_name.to_owned(),
        code: code.to_owned(),
        message: source.to_string(),
    })
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
    use xray_routing::{DomainNameMode, IpMatcherSet};

    use super::{
        cidr_to_ip_cidr, find_entry_body, geodata_wire, scan_entry_code, validate_geo_ip_body,
        validate_geo_site_body, DecodedSite, GeoCidr, GeoDomain, GeoDomainAttribute, GeoDomainType,
        GeoIp, GeoSite, GeodataCache, GeodataError, GeodataLoader, MAX_GEODATA_DOMAINS,
        MAX_GEODATA_ENTRY_SIZE, MAX_GEODATA_FILE_SIZE, MAX_GEODATA_INDEX_ENTRIES,
    };
    use crate::DomainMatcher;

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

    fn private_cache() -> Arc<GeodataCache> {
        Arc::new(GeodataCache::new(usize::MAX))
    }

    fn suffix_domain(value: &str, attrs: &[&str]) -> GeoDomain {
        GeoDomain {
            r#type: GeoDomainType::Domain as i32,
            value: value.to_owned(),
            attribute: attrs
                .iter()
                .map(|key| GeoDomainAttribute {
                    key: (*key).to_owned(),
                })
                .collect(),
        }
    }

    fn write_sites(path: &std::path::Path, sites: &[GeoSite]) {
        let bodies = sites
            .iter()
            .map(|site| site.encode_to_vec())
            .collect::<Vec<_>>();
        write_entry_file(path, &bodies);
    }

    fn write_geoips(path: &std::path::Path, geoips: &[GeoIp]) {
        let bodies = geoips
            .iter()
            .map(|geoip| geoip.encode_to_vec())
            .collect::<Vec<_>>();
        write_entry_file(path, &bodies);
    }

    fn three_domain_site() -> GeoSite {
        GeoSite {
            code: "TEST".to_owned(),
            domain: (0..3)
                .map(|index| suffix_domain(&format!("{index}.example"), &["ads"]))
                .collect(),
        }
    }

    fn v4_cidr(a: u8, b: u8, c: u8, prefix: u32) -> GeoCidr {
        GeoCidr {
            ip: vec![a, b, c, 0],
            prefix,
        }
    }

    #[test]
    fn compiled_categories_are_shared_across_loaders() {
        let root = unique_temp_dir("shared-site");
        write_sites(&root.join("geosite.dat"), &[three_domain_site()]);
        let cache = private_cache();

        let mut first = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        let compiled = first
            .load_site_patterns("geosite.dat", "test", &[], DomainNameMode::Routing, 3)
            .unwrap();
        assert_eq!(compiled.source_count(), 3);
        assert!(compiled.matches("www.1.EXAMPLE"));
        assert_eq!((first.site_decodes, first.index_builds), (1, 1));

        let mut second = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        let reused = second
            .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Routing, 3)
            .unwrap();
        assert!(Arc::ptr_eq(&compiled, &reused));
        assert_eq!(
            (second.site_decodes, second.index_builds),
            (0, 0),
            "a cached category is neither indexed nor decoded again"
        );
        assert_eq!(cache.stats().hits, 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_geosite_over_budget_is_rejected_without_decoding() {
        let root = unique_temp_dir("site-budget");
        write_sites(&root.join("geosite.dat"), &[three_domain_site()]);
        let cache = private_cache();
        let mut first = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        first
            .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Routing, 3)
            .unwrap();

        let mut second = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        let error = second
            .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Routing, 2)
            .unwrap_err();
        assert!(matches!(
            error,
            GeodataError::DomainMatcherBudgetExceeded {
                expanded: 3,
                remaining: 2,
                ..
            }
        ));
        assert_eq!(second.site_decodes, 0);

        let mut cold = GeodataLoader::with_cache(vec![root.clone()], private_cache());
        let error = cold
            .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Routing, 2)
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
            cold.cache.stats().entries,
            0,
            "a rejected category is not cached"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attribute_selections_are_cached_per_normalized_filter() {
        let root = unique_temp_dir("site-attrs");
        let mut site = three_domain_site();
        site.domain.push(suffix_domain("clean.example", &["other"]));
        site.domain
            .push(suffix_domain("both.example", &["ADS", "cn"]));
        write_sites(&root.join("geosite.dat"), &[site]);
        let cache = private_cache();
        let mut loader = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));

        let ads = loader
            .load_site_patterns(
                "geosite.dat",
                "TEST",
                &["ads".to_owned()],
                DomainNameMode::Routing,
                10,
            )
            .unwrap();
        assert_eq!(ads.source_count(), 4);
        assert!(ads.matches("both.example") && !ads.matches("clean.example"));
        let same = loader
            .load_site_patterns(
                "geosite.dat",
                "TEST",
                &["ADS".to_owned(), "ads".to_owned()],
                DomainNameMode::Routing,
                10,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&ads, &same));
        let both = loader
            .load_site_patterns(
                "geosite.dat",
                "TEST",
                &["cn".to_owned(), "ads".to_owned()],
                DomainNameMode::Routing,
                10,
            )
            .unwrap();
        assert_eq!(both.source_count(), 1);
        assert!(both.matches("www.both.example") && !both.matches("1.example"));
        let error = loader
            .load_site_patterns(
                "geosite.dat",
                "TEST",
                &["ads".to_owned()],
                DomainNameMode::Routing,
                3,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            GeodataError::DomainMatcherBudgetExceeded {
                expanded: 4,
                remaining: 3,
                ..
            }
        ));
        assert_eq!(loader.site_decodes, 2);
        assert_eq!(loader.index_builds, 1);

        let matchers = loader
            .load_site_matchers("geosite.dat", "TEST", &["cn".to_owned()], 10)
            .unwrap();
        assert_eq!(matchers, [DomainMatcher::Suffix("both.example".to_owned())]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn categories_compile_once_for_both_modes_unless_a_name_ends_with_a_dot() {
        let root = unique_temp_dir("site-modes");
        let dotted = GeoSite {
            code: "DOTTED".to_owned(),
            domain: vec![suffix_domain("dotted.example.", &[])],
        };
        write_sites(&root.join("geosite.dat"), &[three_domain_site(), dotted]);
        let cache = private_cache();
        let mut loader = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));

        let routing = loader
            .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Routing, 10)
            .unwrap();
        let dns = loader
            .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Dns, 10)
            .unwrap();
        assert!(Arc::ptr_eq(&routing, &dns));

        let routing = loader
            .load_site_patterns("geosite.dat", "DOTTED", &[], DomainNameMode::Routing, 10)
            .unwrap();
        let dns = loader
            .load_site_patterns("geosite.dat", "DOTTED", &[], DomainNameMode::Dns, 10)
            .unwrap();
        assert!(!Arc::ptr_eq(&routing, &dns));
        assert!(routing.matches("a.dotted.example.") && !routing.matches("a.dotted.example"));
        assert!(dns.matches("a.dotted.example") && !dns.matches("a.dotted.example."));
        assert_eq!(loader.site_decodes, 3);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_rewritten_file_is_compiled_again() {
        let root = unique_temp_dir("rewritten");
        let path = root.join("geosite.dat");
        let site = |value: &str| GeoSite {
            code: "TEST".to_owned(),
            domain: vec![suffix_domain(value, &[])],
        };
        write_sites(&path, &[site("old.example")]);
        let cache = private_cache();
        let load = || {
            let mut loader = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
            let patterns = loader
                .load_site_patterns("geosite.dat", "TEST", &[], DomainNameMode::Routing, 10)
                .unwrap();
            (patterns, loader.site_decodes)
        };

        let (old, decodes) = load();
        assert_eq!(decodes, 1);
        assert!(old.matches("old.example"));
        drop(old);

        // Rewritten in place with another size.
        write_sites(&path, &[site("newer.example")]);
        let (new, decodes) = load();
        assert_eq!(decodes, 1);
        assert!(new.matches("newer.example") && !new.matches("old.example"));
        assert_eq!(
            cache.stats().entries,
            1,
            "the unused entry of the replaced version is dropped"
        );
        let (again, decodes) = load();
        assert_eq!(decodes, 0);
        assert!(Arc::ptr_eq(&new, &again));

        // Replaced by a file of the same size, as a host's atomic update does.
        let staged = root.join("geosite.dat.new");
        write_sites(&staged, &[site("other.example")]);
        fs::rename(&staged, &path).unwrap();
        let (replaced, decodes) = load();
        assert_eq!(decodes, 1);
        assert!(replaced.matches("other.example") && !replaced.matches("newer.example"));
        assert!(!Arc::ptr_eq(&new, &replaced));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_geoip_is_shared_and_its_budget_checked_without_decoding() {
        let root = unique_temp_dir("geoip-shared");
        write_geoips(
            &root.join("geoip.dat"),
            &[GeoIp {
                code: "TEST".to_owned(),
                cidr: vec![v4_cidr(192, 0, 2, 24), v4_cidr(198, 51, 100, 24)],
                reverse_match: false,
            }],
        );
        let cache = private_cache();
        let mut first = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        let mut matchers = IpMatcherSet::builder();
        assert_eq!(
            first
                .load_ip_matchers("geoip.dat", "test", false, 2, &mut matchers)
                .unwrap(),
            2
        );
        assert_eq!(matchers.matcher_count(), 2);
        let first_set = matchers.build();
        assert!(first_set.matches("198.51.100.7".parse().unwrap()));
        assert!(!first_set.matches("203.0.113.7".parse().unwrap()));
        assert_eq!(first.ip_decodes, 1);

        let mut second = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        let mut matchers = IpMatcherSet::builder();
        second
            .load_ip_matchers("geoip.dat", "TEST", false, 2, &mut matchers)
            .unwrap();
        assert_eq!(matchers.build(), first_set);
        let error = second
            .load_ip_matchers("geoip.dat", "TEST", false, 1, &mut IpMatcherSet::builder())
            .unwrap_err();
        assert!(matches!(
            error,
            GeodataError::IpMatcherBudgetExceeded {
                expanded: 2,
                remaining: 1,
                ..
            }
        ));
        assert_eq!(second.ip_decodes, 0);
        let stats = cache.stats();
        assert_eq!((stats.entries, stats.hits, stats.misses), (1, 2, 1));
        assert!(
            stats.referenced_bytes > 0,
            "the built set still uses the cached ranges"
        );
        drop(first_set);
        assert_eq!(cache.stats().referenced_bytes, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_entries_fail_as_before_and_are_not_cached() {
        let root = unique_temp_dir("invalid-entries");
        write_sites(
            &root.join("geosite.dat"),
            &[
                GeoSite {
                    code: "EMPTY".to_owned(),
                    domain: vec![suffix_domain("", &[])],
                },
                GeoSite {
                    code: "TYPE".to_owned(),
                    domain: vec![GeoDomain {
                        r#type: 9,
                        value: "x".to_owned(),
                        attribute: Vec::new(),
                    }],
                },
                GeoSite {
                    code: "REGEX".to_owned(),
                    domain: vec![GeoDomain {
                        r#type: GeoDomainType::Regex as i32,
                        value: "(".to_owned(),
                        attribute: Vec::new(),
                    }],
                },
            ],
        );
        write_geoips(
            &root.join("geoip.dat"),
            &[GeoIp {
                code: "BAD".to_owned(),
                cidr: vec![GeoCidr {
                    ip: vec![1, 2, 3],
                    prefix: 8,
                }],
                reverse_match: false,
            }],
        );
        let cache = private_cache();
        let mut loader = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));
        let mut site = |code| {
            loader
                .load_site_patterns("geosite.dat", code, &[], DomainNameMode::Routing, 10)
                .unwrap_err()
        };
        assert!(matches!(site("EMPTY"), GeodataError::InvalidDomain { .. }));
        assert!(matches!(
            site("TYPE"),
            GeodataError::UnsupportedDomainType { domain_type: 9, .. }
        ));
        assert!(matches!(
            site("REGEX"),
            GeodataError::InvalidDomainMatcher { .. }
        ));
        assert!(matches!(site("MISSING"), GeodataError::CodeNotFound { .. }));
        assert!(matches!(
            loader.load_ip_matchers("geoip.dat", "BAD", false, 10, &mut IpMatcherSet::builder()),
            Err(GeodataError::InvalidCidr { .. })
        ));
        assert_eq!(cache.stats().entries, 0);

        fs::remove_dir_all(root).unwrap();
    }

    /// A rule that is only validated, as Xray-core's `checkFile` validates
    /// a filter's, finds its code in the index: no entry is decoded and no
    /// matcher is built.
    #[test]
    fn checking_a_code_reads_only_the_index() {
        let root = unique_temp_dir("check-code");
        let body = GeoIp {
            code: "TEST".to_owned(),
            cidr: vec![GeoCidr {
                ip: vec![192, 0, 2, 0],
                prefix: 24,
            }],
            reverse_match: false,
        }
        .encode_to_vec();
        let mut bytes = vec![0x0a];
        encode_varint(body.len() as u64, &mut bytes);
        bytes.extend_from_slice(&body);
        fs::write(root.join("geoip.dat"), bytes).unwrap();
        let cache = private_cache();
        let mut loader = GeodataLoader::with_cache(vec![root.clone()], Arc::clone(&cache));

        loader.check_code("geoip.dat", "test").unwrap();
        loader.check_code("geoip.dat", "TEST").unwrap();
        assert!(matches!(
            loader.check_code("geoip.dat", "private"),
            Err(GeodataError::CodeNotFound { code, .. }) if code == "PRIVATE"
        ));
        assert!(matches!(
            loader.check_code("other.dat", "TEST"),
            Err(GeodataError::FileNotFound { .. })
        ));
        assert_eq!(loader.index_builds, 1);
        assert_eq!(loader.ip_decodes, 0);
        assert_eq!(cache.stats().entries, 0, "no entry was decoded");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multiple_codes_share_one_pinned_file_index() {
        let root = unique_temp_dir("shared-index");
        write_sites(
            &root.join("geosite.dat"),
            &[
                GeoSite {
                    code: "FIRST".to_owned(),
                    domain: vec![suffix_domain("first.example", &[])],
                },
                GeoSite {
                    code: "SECOND".to_owned(),
                    domain: vec![suffix_domain("second.example", &[])],
                },
            ],
        );
        let mut loader = GeodataLoader::with_cache(vec![root.clone()], private_cache());

        for code in ["FIRST", "SECOND"] {
            let patterns = loader
                .load_site_patterns("geosite.dat", code, &[], DomainNameMode::Routing, 10)
                .unwrap();
            assert!(patterns.matches(&format!("{}.example", code.to_ascii_lowercase())));
        }
        assert_eq!(loader.index_builds, 1);

        fs::remove_dir_all(root).unwrap();
    }

    /// What prost decodes a `GeoSite` body to, in the zero-copy reader's
    /// terms: the code and every domain's type, value and attribute keys.
    type SiteView = (String, Vec<(i32, String, Vec<String>)>);

    fn prost_site(body: &[u8]) -> Option<SiteView> {
        let site = GeoSite::decode(body).ok()?;
        Some((
            site.code,
            site.domain
                .into_iter()
                .map(|domain| {
                    (
                        domain.r#type,
                        domain.value,
                        domain.attribute.into_iter().map(|a| a.key).collect(),
                    )
                })
                .collect(),
        ))
    }

    fn wire_site(body: &[u8]) -> Result<SiteView, geodata_wire::Unsupported> {
        let code = geodata_wire::site_code(body)?.to_owned();
        let domains = geodata_wire::site_domains(body)
            .map(|domain| {
                domain.map(|domain| {
                    (
                        domain.kind,
                        domain.value.to_owned(),
                        domain.attribute_keys().map(str::to_owned).collect(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((code, domains))
    }

    type GeoIpView = (String, bool, Vec<(Vec<u8>, u32)>);

    fn prost_geoip(body: &[u8]) -> Option<GeoIpView> {
        let geoip = GeoIp::decode(body).ok()?;
        Some((
            geoip.code,
            geoip.reverse_match,
            geoip
                .cidr
                .into_iter()
                .map(|cidr| (cidr.ip, cidr.prefix))
                .collect(),
        ))
    }

    fn wire_geoip(body: &[u8]) -> Result<GeoIpView, geodata_wire::Unsupported> {
        let header = geodata_wire::geoip_header(body)?;
        let cidrs = geodata_wire::geoip_cidrs(body)
            .map(|cidr| cidr.map(|cidr| (cidr.ip.to_vec(), cidr.prefix)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((header.code.to_owned(), header.reverse_match, cidrs))
    }

    /// The zero-copy readers either decline a body or read exactly what
    /// prost decodes from it.
    fn assert_wire_agrees_with_prost(body: &[u8]) -> bool {
        let site = wire_site(body);
        if let Ok(view) = &site {
            assert_eq!(Some(view), prost_site(body).as_ref(), "geosite {body:02x?}");
        }
        let geoip = wire_geoip(body);
        if let Ok(view) = &geoip {
            assert_eq!(Some(view), prost_geoip(body).as_ref(), "geoip {body:02x?}");
        }
        site.is_ok()
    }

    fn field(output: &mut Vec<u8>, number: u64, wire_type: u64) {
        encode_varint((number << 3) | wire_type, output);
    }

    fn bytes_field(output: &mut Vec<u8>, number: u64, value: &[u8]) {
        field(output, number, 2);
        encode_varint(value.len() as u64, output);
        output.extend_from_slice(value);
    }

    fn varint_field(output: &mut Vec<u8>, number: u64, value: u64) {
        field(output, number, 0);
        encode_varint(value, output);
    }

    #[test]
    fn zero_copy_reader_matches_prost_on_edge_cases() {
        let attribute = |key: &[u8], extra: &[u8]| {
            let mut body = Vec::new();
            bytes_field(&mut body, 1, key);
            body.extend_from_slice(extra);
            body
        };
        let domain = |kind: u64, value: &[u8], attributes: &[Vec<u8>]| {
            let mut body = Vec::new();
            varint_field(&mut body, 1, kind);
            bytes_field(&mut body, 2, value);
            for attribute in attributes {
                bytes_field(&mut body, 3, attribute);
            }
            body
        };
        let site = |code: &[u8], domains: &[Vec<u8>], extra: &[u8]| {
            let mut body = Vec::new();
            bytes_field(&mut body, 1, code);
            for domain in domains {
                bytes_field(&mut body, 2, domain);
            }
            body.extend_from_slice(extra);
            body
        };

        let mut unknown = Vec::new();
        varint_field(&mut unknown, 9, 300);
        field(&mut unknown, 10, 1);
        unknown.extend_from_slice(&[0; 8]);
        field(&mut unknown, 11, 5);
        unknown.extend_from_slice(&[0; 4]);
        bytes_field(&mut unknown, 12, b"skipped");
        let mut bool_attribute = Vec::new();
        varint_field(&mut bool_attribute, 2, 1);
        let mut group = Vec::new();
        field(&mut group, 4, 3);
        field(&mut group, 4, 4);
        let mut duplicate = domain(2, b"first.example", &[]);
        varint_field(&mut duplicate, 1, 3);
        bytes_field(&mut duplicate, 2, b"last.example");
        let mut negative = Vec::new();
        varint_field(&mut negative, 1, u64::MAX);
        let mut wrong_type = Vec::new();
        bytes_field(&mut wrong_type, 1, b"x");

        let plain = [
            site(b"TEST", &[domain(2, b"a.example", &[])], &[]),
            site(
                b"TEST",
                &[domain(0, b"kw", &[attribute(b"Ads", &bool_attribute)])],
                &unknown,
            ),
            site(b"TEST", &[duplicate.clone()], &[]),
            site(b"TEST", &[negative], &[]),
            site(b"TEST", &[[duplicate.as_slice(), &unknown].concat()], &[]),
            {
                let mut twice = site(b"OLD", &[], &[]);
                twice.extend(site(b"NEW", &[domain(3, b"b.example", &[])], &[]));
                twice
            },
            Vec::new(),
        ];
        for body in &plain {
            assert!(assert_wire_agrees_with_prost(body), "declined {body:02x?}");
        }
        assert_eq!(
            wire_site(&plain[2]).unwrap().1,
            [(3, "last.example".to_owned(), Vec::new())]
        );

        let declined = [
            site(b"TEST", &[domain(2, b"\xff.example", &[])], &[]),
            site(b"\xff", &[], &[]),
            site(b"TEST", &[domain(2, b"a", &[attribute(b"\xff", &[])])], &[]),
            site(b"TEST", &[domain(2, b"a", &[attribute(b"k", &group)])], &[]),
            site(b"TEST", &[wrong_type], &[]),
            site(b"TEST", &[], &group),
            vec![0x0a, 0x05, b'a'],
            vec![
                0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ],
            vec![0x00, 0x00],
        ];
        for body in &declined {
            assert!(!assert_wire_agrees_with_prost(body), "accepted {body:02x?}");
        }
        assert!(
            prost_site(&declined[3]).is_some(),
            "prost skips a group inside an attribute, so the loader falls back to it"
        );

        let mut geoip = Vec::new();
        bytes_field(&mut geoip, 1, b"TEST");
        let mut cidr = Vec::new();
        bytes_field(&mut cidr, 1, &[192, 0, 2, 0]);
        varint_field(&mut cidr, 2, (1 << 32) + 24);
        bytes_field(&mut geoip, 2, &cidr);
        varint_field(&mut geoip, 3, 2);
        geoip.extend_from_slice(&unknown);
        assert_eq!(
            wire_geoip(&geoip).unwrap(),
            ("TEST".to_owned(), true, vec![(vec![192, 0, 2, 0], 24)])
        );
        assert_wire_agrees_with_prost(&geoip);
    }

    #[test]
    fn zero_copy_reader_matches_prost_on_mutated_bodies() {
        let mut site = three_domain_site();
        site.domain.push(GeoDomain {
            r#type: GeoDomainType::Regex as i32,
            value: "^a[0-9]+$".to_owned(),
            attribute: vec![GeoDomainAttribute {
                key: "cn".to_owned(),
            }],
        });
        let site = site.encode_to_vec();
        let geoip = GeoIp {
            code: "TEST".to_owned(),
            cidr: vec![
                v4_cidr(192, 0, 2, 24),
                GeoCidr {
                    ip: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    prefix: 32,
                },
            ],
            reverse_match: true,
        }
        .encode_to_vec();

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0;
        for round in 0..20_000 {
            let mut body = if round % 2 == 0 {
                site.clone()
            } else {
                geoip.clone()
            };
            for _ in 0..=next() % 3 {
                let index = (next() % body.len() as u64) as usize;
                match next() % 4 {
                    0 => body[index] = next() as u8,
                    1 => body[index] ^= 1 << (next() % 8),
                    2 => body.truncate(index),
                    _ => body.insert(index, next() as u8),
                }
                if body.is_empty() {
                    break;
                }
            }
            if assert_wire_agrees_with_prost(&body) || wire_geoip(&body).is_ok() {
                accepted += 1;
            }
        }
        assert!(
            accepted > 1_000,
            "only {accepted} mutated bodies were plain"
        );
    }

    /// The reference the packed matchers replace: one hash set per name kind,
    /// probed per label, as `DomainMatcherSet` compiled geosite categories
    /// before.
    struct ReferenceMatcher {
        full: std::collections::HashSet<String>,
        suffix: std::collections::HashSet<String>,
        others: Vec<DomainMatcher>,
    }

    impl ReferenceMatcher {
        fn new(matchers: &[DomainMatcher], mode: DomainNameMode) -> Self {
            let mut reference = Self {
                full: Default::default(),
                suffix: Default::default(),
                others: Vec::new(),
            };
            let pattern = |name: &str| match mode {
                DomainNameMode::Routing => name.to_ascii_lowercase(),
                DomainNameMode::Dns => name.trim_end_matches('.').to_ascii_lowercase(),
            };
            for matcher in matchers {
                match matcher {
                    DomainMatcher::Full(name) => {
                        reference.full.insert(pattern(name));
                    }
                    DomainMatcher::Suffix(name) => {
                        reference.suffix.insert(pattern(name));
                    }
                    other => reference.others.push(other.clone()),
                }
            }
            reference
        }

        fn matches(&self, domain: &str) -> bool {
            let domain = domain.to_ascii_lowercase();
            self.full.contains(&domain)
                || self.suffix.contains(&domain)
                || domain
                    .rmatch_indices('.')
                    .any(|(index, _)| self.suffix.contains(&domain[index + 1..]))
                || self.others.iter().any(|matcher| matcher.matches(&domain))
        }
    }

    fn equivalence_probes(matchers: &[DomainMatcher]) -> Vec<String> {
        let mut probes = vec![String::new(), ".".to_owned(), "example.com".to_owned()];
        for matcher in matchers {
            let name = match matcher {
                DomainMatcher::Full(name)
                | DomainMatcher::Suffix(name)
                | DomainMatcher::Keyword(name) => name.clone(),
                DomainMatcher::Regex(_) => continue,
            };
            probes.push(format!("www.{name}"));
            probes.push(name.to_ascii_uppercase());
            probes.push(format!("{name}."));
            probes.push(format!("x{name}"));
            if let Some((_, parent)) = name.split_once('.') {
                probes.push(parent.to_owned());
            }
            probes.push(name);
        }
        probes
    }

    /// Every category of a real `geosite.dat` and `geoip.dat` compiles to
    /// matchers that answer as the prost-decoded, per-name reference does.
    /// Run with `XRAY_GEODATA_TEST_DIR=<dir> cargo test -p xray-config --lib
    /// real_geodata -- --ignored`.
    #[test]
    #[ignore = "needs XRAY_GEODATA_TEST_DIR with geosite.dat and geoip.dat"]
    fn real_geodata_compiles_like_the_reference() {
        let dir = PathBuf::from(
            std::env::var_os("XRAY_GEODATA_TEST_DIR").expect("XRAY_GEODATA_TEST_DIR is set"),
        );
        let mut loader = GeodataLoader::with_cache(vec![dir.clone()], private_cache());

        let site_codes = loader
            .indexed_file("geosite.dat")
            .unwrap()
            .entries
            .clone()
            .unwrap();
        let mut checked_names = 0;
        for code in site_codes.keys() {
            let (body, path) = loader
                .read_entry("geosite.dat", code, validate_geo_site_body)
                .unwrap();
            assert_eq!(
                wire_site(&body).ok(),
                prost_site(&body),
                "zero-copy and prost decodes of geosite:{code}"
            );
            let site = GeoSite::decode(body.as_slice()).unwrap();
            let mut attrs = site
                .domain
                .iter()
                .flat_map(|domain| {
                    domain
                        .attribute
                        .iter()
                        .map(|attr| attr.key.to_ascii_lowercase())
                })
                .collect::<Vec<_>>();
            attrs.sort_unstable();
            attrs.dedup();
            let filters = std::iter::once(Vec::new())
                .chain(attrs.into_iter().map(|attr| vec![attr]))
                .collect::<Vec<_>>();
            for filter in &filters {
                let reference = DecodedSite::Prost(site.clone());
                let mut matchers = Vec::new();
                reference
                    .for_each_selected(filter, &path, |domain| {
                        matchers.push(domain.to_matcher("geosite.dat", code)?);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(
                    loader
                        .load_site_matchers("geosite.dat", code, filter, usize::MAX)
                        .unwrap(),
                    matchers,
                    "geosite:{code}@{filter:?} matchers"
                );
                let probes = equivalence_probes(&matchers);
                for mode in [DomainNameMode::Routing, DomainNameMode::Dns] {
                    let expected = ReferenceMatcher::new(&matchers, mode);
                    let compiled = loader
                        .load_site_patterns("geosite.dat", code, filter, mode, usize::MAX)
                        .unwrap();
                    assert_eq!(compiled.source_count(), matchers.len());
                    for probe in &probes {
                        assert_eq!(
                            compiled.matches(probe),
                            expected.matches(probe),
                            "geosite:{code}@{filter:?} {mode:?} `{probe}`"
                        );
                    }
                    checked_names += probes.len();
                }
            }
        }

        let ip_codes = loader
            .indexed_file("geoip.dat")
            .unwrap()
            .entries
            .clone()
            .unwrap();
        for code in ip_codes.keys() {
            let (body, _) = loader
                .read_entry("geoip.dat", code, validate_geo_ip_body)
                .unwrap();
            assert_eq!(
                wire_geoip(&body).ok(),
                prost_geoip(&body),
                "zero-copy and prost decodes of geoip:{code}"
            );
            let geoip = GeoIp::decode(body.as_slice()).unwrap();
            let mut expected = IpMatcherSet::builder();
            for cidr in &geoip.cidr {
                expected.insert_geoip_cidr(
                    cidr_to_ip_cidr(&cidr.ip, cidr.prefix, "geoip.dat", code)
                        .unwrap()
                        .cidr(),
                    geoip.reverse_match,
                );
            }
            let mut compiled = IpMatcherSet::builder();
            loader
                .load_ip_matchers("geoip.dat", code, false, usize::MAX, &mut compiled)
                .unwrap();
            assert_eq!(compiled.matcher_count(), expected.matcher_count());
            assert_eq!(compiled.build(), expected.build(), "geoip:{code}");
        }
        eprintln!(
            "checked {} geosite and {} geoip categories, {checked_names} probes",
            site_codes.len(),
            ip_codes.len()
        );
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
