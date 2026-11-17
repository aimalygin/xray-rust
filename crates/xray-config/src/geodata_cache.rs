//! Process-wide cache of compiled geodata categories.
//!
//! A mobile host restarts the core, with a new handle in the same process, on
//! every server switch, and every start parses the configuration again. The
//! geosite and geoip categories it references compile to the same matchers
//! each time, so the compiled [`DomainPatternSet`]s and [`IpRangeSet`]s are
//! kept here and handed by reference (`Arc`) to every configuration that asks
//! for the same category of the same file.
//!
//! An entry is keyed by the file's identity (path, device and inode, size,
//! modification and status-change times), the normalized code, the attribute
//! filter and, for domains, the name mode when it changes the result. A file
//! the host replaces or rewrites gets a new identity, so its old entries are
//! never returned again; unused ones are dropped as soon as the file's new
//! identity is cached.
//!
//! A rewrite in place that keeps the size and lands within one tick of the
//! file's timestamps keeps its identity too, and timestamp ticks are coarse on
//! some file systems. What was read from a file whose modification or
//! status-change time is within [`GEODATA_SETTLE_TIME`] of when it was opened
//! is therefore not cached here: any later change of such a file moves its
//! timestamps to a later tick.
//!
//! Entries that a live configuration still references cost nothing extra and
//! are always kept. Entries no configuration references any more are kept,
//! most recently used first, up to [`RETAINED_UNUSED_GEODATA_BYTES`], so a core that
//! is stopped before its replacement starts still leaves its categories to
//! the next one; older ones are released.

use std::collections::HashMap;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use xray_routing::{DomainNameMode, DomainPatternSet, IpRangeSet};

/// Estimated heap bytes of compiled categories kept while no configuration
/// references them.
pub const RETAINED_UNUSED_GEODATA_BYTES: usize = 4 * 1024 * 1024;

/// How far a geodata file's modification and status-change times must be
/// from the moment it is opened for what is read from it to be cached for the
/// process. Two seconds covers the coarsest timestamp tick in use, FAT's.
pub(crate) const GEODATA_SETTLE_TIME: Duration = Duration::from_secs(2);

/// What identifies one version of a geodata file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed: (i64, i64),
}

impl FileIdentity {
    pub(crate) fn new(path: &Path, metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            path: path.to_path_buf(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    /// Whether the file's modification and status-change times are both at
    /// least `settle_time` away from `now`, before or after it. A file that
    /// settled when it was opened cannot change without moving its
    /// status-change time to another tick, so the identity taken then still
    /// names what was read. Unknown times count as unsettled.
    pub(crate) fn settled(&self, now: SystemTime, settle_time: Duration) -> bool {
        let apart = |time: SystemTime| match now.duration_since(time) {
            Ok(elapsed) => elapsed >= settle_time,
            Err(ahead) => ahead.duration() >= settle_time,
        };
        #[cfg(unix)]
        let changed = unix_time(self.changed).is_some_and(apart);
        #[cfg(not(unix))]
        let changed = true;
        changed && self.modified.is_some_and(apart)
    }
}

/// The `SystemTime` of a Unix timestamp in seconds and nanoseconds.
#[cfg(unix)]
fn unix_time((seconds, nanoseconds): (i64, i64)) -> Option<SystemTime> {
    use std::time::UNIX_EPOCH;

    let nanoseconds = u64::try_from(nanoseconds)
        .ok()
        .filter(|nanoseconds| *nanoseconds < 1_000_000_000)?;
    let whole = Duration::from_secs(seconds.unsigned_abs());
    let seconds = if seconds < 0 {
        UNIX_EPOCH.checked_sub(whole)
    } else {
        UNIX_EPOCH.checked_add(whole)
    }?;
    seconds.checked_add(Duration::from_nanos(nanoseconds))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SiteKey {
    file: FileIdentity,
    code: String,
    attrs: Vec<String>,
    /// `None` when both modes compile the category alike, as they do unless
    /// a `full:` or `domain:` name ends with a dot.
    mode: Option<DomainNameMode>,
}

impl SiteKey {
    /// `code` is normalized by the caller; `attrs` are matched ASCII
    /// case-insensitively and all of them must hold, so they are lowercased,
    /// sorted and deduplicated here.
    pub(crate) fn new(
        file: FileIdentity,
        code: &str,
        attrs: &[String],
        mode: DomainNameMode,
    ) -> Self {
        let mut attrs = attrs
            .iter()
            .map(|attr| attr.to_ascii_lowercase())
            .collect::<Vec<_>>();
        attrs.sort_unstable();
        attrs.dedup();
        Self {
            file,
            code: code.to_owned(),
            attrs,
            mode: Some(mode),
        }
    }

    pub(crate) fn attrs(&self) -> &[String] {
        &self.attrs
    }

    /// The same key for a category that compiles alike in both modes.
    pub(crate) fn mode_independent(mut self) -> Self {
        self.mode = None;
        self
    }

    fn with_mode(&self, mode: Option<DomainNameMode>) -> Self {
        Self {
            mode,
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct IpKey {
    file: FileIdentity,
    code: String,
}

impl IpKey {
    pub(crate) fn new(file: FileIdentity, code: &str) -> Self {
        Self {
            file,
            code: code.to_owned(),
        }
    }
}

/// A compiled GeoIP category: its merged ranges, the CIDRs they came from,
/// and the entry's legacy `reverse_match` flag.
#[derive(Debug, Clone)]
pub(crate) struct GeoIpEntry {
    pub(crate) ranges: IpRangeSet,
    pub(crate) cidr_count: usize,
    pub(crate) reverse_match: bool,
}

/// Counters of the process-wide geodata cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeodataCacheStats {
    /// Categories cached, in use or not.
    pub entries: usize,
    /// Estimated heap bytes of the cached categories some configuration
    /// still references.
    pub referenced_bytes: usize,
    /// Estimated heap bytes of the cached categories no configuration
    /// references, kept for the next one.
    pub unused_bytes: usize,
    /// Lookups answered from the cache since the process started.
    pub hits: u64,
    /// Categories compiled since the process started.
    pub misses: u64,
}

#[derive(Debug)]
pub(crate) struct GeodataCache {
    state: Mutex<CacheState>,
    retained_unused_bytes: usize,
    settle_time: Duration,
}

#[derive(Debug, Default)]
struct CacheState {
    sites: HashMap<SiteKey, Entry<Arc<DomainPatternSet>>>,
    ips: HashMap<IpKey, Entry<GeoIpEntry>>,
    clock: u64,
    hits: u64,
    misses: u64,
}

#[derive(Debug)]
struct Entry<T> {
    value: T,
    bytes: usize,
    last_used: u64,
}

trait Shared {
    /// Whether a configuration references the value besides the cache.
    fn in_use(&self) -> bool;
}

impl Shared for Arc<DomainPatternSet> {
    fn in_use(&self) -> bool {
        Arc::strong_count(self) > 1
    }
}

impl Shared for GeoIpEntry {
    fn in_use(&self) -> bool {
        self.ranges.share_count() > 1
    }
}

impl GeodataCache {
    /// A cache that keeps up to `retained_unused_bytes` of unused categories
    /// and takes those of files that settled `settle_time` before they were
    /// opened.
    pub(crate) fn new(retained_unused_bytes: usize, settle_time: Duration) -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
            retained_unused_bytes,
            settle_time,
        }
    }

    /// The cache every parser in this process shares.
    pub(crate) fn global() -> &'static Arc<Self> {
        static GLOBAL: OnceLock<Arc<GeodataCache>> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            Arc::new(Self::new(
                RETAINED_UNUSED_GEODATA_BYTES,
                GEODATA_SETTLE_TIME,
            ))
        })
    }

    /// Whether what was read from a file with identity `file`, taken at
    /// `identified_at`, may be cached here.
    pub(crate) fn accepts(&self, file: &FileIdentity, identified_at: SystemTime) -> bool {
        file.settled(identified_at, self.settle_time)
    }

    fn lock(&self) -> MutexGuard<'_, CacheState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn site(&self, key: &SiteKey) -> Option<Arc<DomainPatternSet>> {
        let mut state = self.lock();
        let state = &mut *state;
        state.clock += 1;
        let mode_independent;
        let key = if state.sites.contains_key(key) {
            key
        } else {
            mode_independent = key.with_mode(None);
            &mode_independent
        };
        let entry = state.sites.get_mut(key)?;
        entry.last_used = state.clock;
        state.hits += 1;
        Some(Arc::clone(&entry.value))
    }

    /// Caches a compiled category and returns the cached one, which is an
    /// equal category another parser compiled meanwhile if there is one.
    pub(crate) fn insert_site(
        &self,
        key: SiteKey,
        patterns: Arc<DomainPatternSet>,
    ) -> Arc<DomainPatternSet> {
        let mut state = self.lock();
        state.clock += 1;
        state.misses += 1;
        state.drop_unused_versions_of(&key.file);
        let clock = state.clock;
        let bytes = patterns.heap_size_estimate();
        let entry = state.sites.entry(key).or_insert(Entry {
            value: patterns,
            bytes,
            last_used: clock,
        });
        entry.last_used = clock;
        let patterns = Arc::clone(&entry.value);
        state.trim(self.retained_unused_bytes);
        patterns
    }

    pub(crate) fn ip(&self, key: &IpKey) -> Option<GeoIpEntry> {
        let mut state = self.lock();
        let state = &mut *state;
        state.clock += 1;
        let entry = state.ips.get_mut(key)?;
        entry.last_used = state.clock;
        state.hits += 1;
        Some(entry.value.clone())
    }

    /// Caches a compiled category and returns the cached one, as
    /// [`Self::insert_site`] does.
    pub(crate) fn insert_ip(&self, key: IpKey, entry: GeoIpEntry) -> GeoIpEntry {
        let mut state = self.lock();
        state.clock += 1;
        state.misses += 1;
        state.drop_unused_versions_of(&key.file);
        let clock = state.clock;
        let bytes = entry.ranges.heap_size();
        let cached = state.ips.entry(key).or_insert(Entry {
            value: entry,
            bytes,
            last_used: clock,
        });
        cached.last_used = clock;
        let entry = cached.value.clone();
        state.trim(self.retained_unused_bytes);
        entry
    }

    /// Releases the unused categories beyond the retention budget, least
    /// recently used first.
    pub(crate) fn trim(&self) {
        self.lock().trim(self.retained_unused_bytes);
    }

    pub(crate) fn stats(&self) -> GeodataCacheStats {
        let state = self.lock();
        let mut stats = GeodataCacheStats {
            entries: state.sites.len() + state.ips.len(),
            hits: state.hits,
            misses: state.misses,
            ..GeodataCacheStats::default()
        };
        let sizes = state
            .sites
            .values()
            .map(|entry| (entry.value.in_use(), entry.bytes))
            .chain(
                state
                    .ips
                    .values()
                    .map(|entry| (entry.value.in_use(), entry.bytes)),
            );
        for (in_use, bytes) in sizes {
            if in_use {
                stats.referenced_bytes += bytes;
            } else {
                stats.unused_bytes += bytes;
            }
        }
        stats
    }
}

impl CacheState {
    /// Drops the unused entries of other versions of `file`'s path: a
    /// replaced file's categories can never be looked up again.
    fn drop_unused_versions_of(&mut self, file: &FileIdentity) {
        let stale = |key_file: &FileIdentity, in_use: bool| {
            !in_use && key_file.path == file.path && key_file != file
        };
        self.sites
            .retain(|key, entry| !stale(&key.file, entry.value.in_use()));
        self.ips
            .retain(|key, entry| !stale(&key.file, entry.value.in_use()));
    }

    fn trim(&mut self, retained_unused_bytes: usize) {
        let mut unused = self
            .sites
            .iter()
            .filter(|(_, entry)| !entry.value.in_use())
            .map(|(key, entry)| (entry.last_used, entry.bytes, Some(key.clone()), None))
            .chain(
                self.ips
                    .iter()
                    .filter(|(_, entry)| !entry.value.in_use())
                    .map(|(key, entry)| (entry.last_used, entry.bytes, None, Some(key.clone()))),
            )
            .collect::<Vec<_>>();
        let mut unused_bytes = unused.iter().map(|(_, bytes, ..)| bytes).sum::<usize>();
        if unused_bytes <= retained_unused_bytes {
            return;
        }
        unused.sort_unstable_by_key(|(last_used, ..)| *last_used);
        for (_, bytes, site, ip) in unused {
            if unused_bytes <= retained_unused_bytes {
                break;
            }
            if let Some(site) = site {
                self.sites.remove(&site);
            }
            if let Some(ip) = ip {
                self.ips.remove(&ip);
            }
            unused_bytes -= bytes;
        }
    }
}

/// Counters of the process-wide geodata cache.
pub fn geodata_cache_stats() -> GeodataCacheStats {
    GeodataCache::global().stats()
}

/// Releases the cached geodata categories that no configuration references,
/// beyond the small budget kept for the next core. The C API does this after
/// every call that parses or drops a configuration; call it after dropping a
/// [`crate::CoreConfig`] or a routing policy in other embeddings.
pub fn trim_geodata_cache() {
    GeodataCache::global().trim();
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_routing::IpRangeSetBuilder;

    fn identity(path: &str, len: u64) -> FileIdentity {
        FileIdentity {
            path: PathBuf::from(path),
            len,
            modified: None,
            #[cfg(unix)]
            device: 1,
            #[cfg(unix)]
            inode: 1,
            #[cfg(unix)]
            changed: (0, 0),
        }
    }

    fn patterns(names: usize) -> Arc<DomainPatternSet> {
        let mut builder = DomainPatternSet::builder();
        for index in 0..names {
            builder.insert_suffix(&format!("name-{index}.example"), DomainNameMode::Routing);
        }
        Arc::new(builder.build().unwrap())
    }

    fn site_key(path: &str, len: u64, code: &str) -> SiteKey {
        SiteKey::new(identity(path, len), code, &[], DomainNameMode::Routing)
    }

    #[test]
    fn referenced_entries_are_kept_and_unused_ones_trimmed_lru_first() {
        let cache = GeodataCache::new(0, Duration::ZERO);
        let first = cache.insert_site(site_key("geosite.dat", 1, "A"), patterns(100));
        let second = cache.insert_site(site_key("geosite.dat", 1, "B"), patterns(100));
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.stats().unused_bytes, 0);

        drop(first);
        cache.trim();
        assert_eq!(cache.stats().entries, 1);
        assert!(cache.site(&site_key("geosite.dat", 1, "A")).is_none());
        let again = cache.site(&site_key("geosite.dat", 1, "B")).unwrap();
        assert!(Arc::ptr_eq(&again, &second));
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 2);
    }

    #[test]
    fn unused_entries_are_retained_up_to_the_budget() {
        let size = patterns(1_000).heap_size_estimate();
        let cache = GeodataCache::new(size * 2, Duration::ZERO);
        for code in ["A", "B", "C"] {
            drop(cache.insert_site(site_key("geosite.dat", 1, code), patterns(1_000)));
        }
        assert_eq!(
            cache.stats().entries,
            3,
            "each was in use when it was inserted"
        );
        cache.trim();
        let stats = cache.stats();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.unused_bytes, size * 2);
        assert!(cache.site(&site_key("geosite.dat", 1, "A")).is_none());
        assert!(cache.site(&site_key("geosite.dat", 1, "C")).is_some());
    }

    #[test]
    fn only_files_whose_timestamps_settled_are_accepted() {
        let opened = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let file = |modified: Option<SystemTime>, changed: SystemTime| {
            #[cfg(not(unix))]
            let _ = changed;
            FileIdentity {
                modified,
                #[cfg(unix)]
                changed: {
                    let since = changed.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                    (
                        i64::try_from(since.as_secs()).unwrap(),
                        i64::from(since.subsec_nanos()),
                    )
                },
                ..identity("geosite.dat", 1)
            }
        };
        let cache = GeodataCache::new(usize::MAX, Duration::from_secs(2));
        let long_ago = opened - Duration::from_secs(60);
        let just_before = opened - Duration::from_millis(1_999);
        let far_ahead = opened + Duration::from_secs(60);

        assert!(cache.accepts(&file(Some(long_ago), long_ago), opened));
        assert!(cache.accepts(
            &file(Some(opened - Duration::from_secs(2)), long_ago),
            opened
        ));
        assert!(cache.accepts(&file(Some(far_ahead), long_ago), opened));
        assert!(!cache.accepts(&file(Some(just_before), long_ago), opened));
        assert!(!cache.accepts(
            &file(Some(opened + Duration::from_secs(1)), long_ago),
            opened
        ));
        assert!(!cache.accepts(&file(None, long_ago), opened));
        #[cfg(unix)]
        {
            // A rewrite that restores the modification time still moves the
            // status-change time.
            assert!(!cache.accepts(&file(Some(long_ago), just_before), opened));
            assert!(unix_time((-1, 500_000_000)).is_some());
            assert!(unix_time((0, 1_000_000_000)).is_none());
        }

        let any = GeodataCache::new(usize::MAX, Duration::ZERO);
        assert!(any.accepts(&file(Some(opened), opened), opened));
    }

    #[test]
    fn a_new_file_version_drops_the_unused_entries_of_the_old_one() {
        let cache = GeodataCache::new(usize::MAX, Duration::ZERO);
        let held = cache.insert_site(site_key("geosite.dat", 1, "HELD"), patterns(1));
        drop(cache.insert_site(site_key("geosite.dat", 1, "FREE"), patterns(1)));
        drop(cache.insert_site(site_key("other.dat", 1, "FREE"), patterns(1)));
        assert_eq!(cache.stats().entries, 3);

        drop(cache.insert_site(site_key("geosite.dat", 2, "FREE"), patterns(1)));
        assert!(cache.site(&site_key("geosite.dat", 1, "FREE")).is_none());
        assert!(cache.site(&site_key("geosite.dat", 1, "HELD")).is_some());
        assert!(cache.site(&site_key("other.dat", 1, "FREE")).is_some());
        assert!(cache.site(&site_key("geosite.dat", 2, "FREE")).is_some());
        drop(held);
    }

    #[test]
    fn mode_independent_entries_serve_both_modes() {
        let cache = GeodataCache::new(usize::MAX, Duration::ZERO);
        let key = SiteKey::new(
            identity("geosite.dat", 1),
            "A",
            &[],
            DomainNameMode::Routing,
        );
        let cached = cache.insert_site(key.mode_independent(), patterns(1));
        let dns = SiteKey::new(identity("geosite.dat", 1), "A", &[], DomainNameMode::Dns);
        assert!(Arc::ptr_eq(&cache.site(&dns).unwrap(), &cached));

        let dotted = SiteKey::new(identity("geosite.dat", 1), "B", &[], DomainNameMode::Dns);
        drop(cache.insert_site(dotted, patterns(1)));
        let routing = SiteKey::new(
            identity("geosite.dat", 1),
            "B",
            &[],
            DomainNameMode::Routing,
        );
        assert!(cache.site(&routing).is_none());
    }

    #[test]
    fn attribute_filters_are_normalized() {
        let file = identity("geosite.dat", 1);
        let key = SiteKey::new(
            file.clone(),
            "A",
            &["Ads".to_owned(), "cn".to_owned(), "ads".to_owned()],
            DomainNameMode::Routing,
        );
        assert_eq!(key.attrs(), ["ads", "cn"]);
        assert_eq!(
            key,
            SiteKey::new(
                file,
                "A",
                &["cn".to_owned(), "ADS".to_owned()],
                DomainNameMode::Routing
            )
        );
    }

    #[test]
    fn concurrent_compiles_converge_on_one_entry() {
        let cache = GeodataCache::new(usize::MAX, Duration::ZERO);
        let first = cache.insert_site(site_key("geosite.dat", 1, "A"), patterns(1));
        let second = cache.insert_site(site_key("geosite.dat", 1, "A"), patterns(1));
        assert!(Arc::ptr_eq(&first, &second));

        let mut builder = IpRangeSetBuilder::new();
        builder.insert_cidr(xray_routing::Cidr::new("192.0.2.0".parse().unwrap(), 24).unwrap());
        let ranges = builder.build();
        let key = IpKey::new(identity("geoip.dat", 1), "A");
        let entry = GeoIpEntry {
            ranges: ranges.clone(),
            cidr_count: 1,
            reverse_match: false,
        };
        let cached = cache.insert_ip(key.clone(), entry.clone());
        let raced = cache.insert_ip(key.clone(), entry);
        assert!(cached.ranges.shares_ranges_with(&raced.ranges));
        assert!(cache.ip(&key).unwrap().ranges.shares_ranges_with(&ranges));
    }
}
