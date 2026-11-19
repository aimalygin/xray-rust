//! Compact, immutable storage for compiled domain patterns.
//!
//! A geosite category can hold tens of thousands of names. Keeping each one
//! in its own heap allocation costs more in allocator headers, hash-table
//! slots and fragmentation than the names themselves, so
//! [`DomainPatternSet`] packs every `full:` and `domain:` name of a set into
//! one byte buffer grouped by a keyed hash, with an end offset and a one-word
//! Bloom filter per bucket of about four names. Keywords share one buffer as
//! well; only regexes keep an allocation each.
//!
//! The set is immutable once built and is meant to be shared behind an
//! [`std::sync::Arc`], so the geodata cache can hand the same compiled
//! category to every rule, DNS selector and core that references it.

use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};

use aho_corasick::{AhoCorasick, AhoCorasickKind, StartKind};
use regex::Regex;

use crate::{DomainMatcher, DomainMatcherSetError, DomainNameMode, RegexMatcher};

/// Average names per hash bucket, between this value and twice it. Buckets
/// are scanned sequentially in one contiguous run of bytes, so a few names per
/// bucket cost little at lookup and keep the bucket table small; each bucket's
/// filter turns most misses away before the names are read.
const NAMES_PER_BUCKET: usize = 4;

/// Rough heap cost of one compiled regex, used only for cache accounting; the
/// regex engine does not report its own size.
const REGEX_HEAP_ESTIMATE: usize = 16 * 1024;

/// Immutable `full:`, `domain:`, `keyword:` and `regexp:` patterns compiled
/// into packed tables.
///
/// Matching follows [`crate::DomainMatcherSet`]: names compare per label and
/// ASCII case-insensitively, `full:` and `domain:` patterns are normalized for
/// the [`DomainNameMode`] they were inserted with, and regexes see the
/// ASCII-lowercased name.
pub struct DomainPatternSet {
    full: PackedNameTable,
    suffix: PackedNameTable,
    keywords: PackedStrings,
    keyword_automaton: Option<AhoCorasick>,
    regex: Box<[Regex]>,
    source_count: usize,
}

impl DomainPatternSet {
    pub fn builder() -> DomainPatternSetBuilder {
        DomainPatternSetBuilder::default()
    }

    /// Returns the number of source patterns inserted, duplicates included.
    pub fn source_count(&self) -> usize {
        self.source_count
    }

    pub fn is_empty(&self) -> bool {
        self.source_count == 0
    }

    /// Distinct `full:` names.
    pub fn full_count(&self) -> usize {
        self.full.len()
    }

    /// Distinct `domain:` suffixes.
    pub fn suffix_count(&self) -> usize {
        self.suffix.len()
    }

    pub fn keyword_count(&self) -> usize {
        self.keywords.len()
    }

    pub fn regex_count(&self) -> usize {
        self.regex.len()
    }

    /// Returns the retained pattern payload in bytes, excluding table,
    /// automaton and regex-engine overhead.
    pub fn pattern_bytes(&self) -> usize {
        self.full.name_bytes()
            + self.suffix.name_bytes()
            + self.keywords.byte_len()
            + self
                .regex
                .iter()
                .map(|regex| regex.as_str().len())
                .sum::<usize>()
    }

    /// Estimates the heap retained by this set: the packed tables exactly,
    /// the keyword automaton as it reports itself, and a fixed estimate per
    /// regex.
    pub fn heap_size_estimate(&self) -> usize {
        self.full.heap_bytes()
            + self.suffix.heap_bytes()
            + self.keywords.heap_bytes()
            + self
                .keyword_automaton
                .as_ref()
                .map_or(0, AhoCorasick::memory_usage)
            + self
                .regex
                .iter()
                .map(|regex| regex.as_str().len() + REGEX_HEAP_ESTIMATE)
                .sum::<usize>()
    }

    pub fn matches(&self, domain: &str) -> bool {
        self.matches_lowercase(&lowercase_ascii(domain))
    }

    /// Matches a name that is already ASCII-lowercased.
    pub(crate) fn matches_lowercase(&self, domain: &str) -> bool {
        self.full.contains(domain.as_bytes())
            || self.matches_suffix(domain)
            || self
                .keyword_automaton
                .as_ref()
                .is_some_and(|automaton| automaton.is_match(domain))
            || self.regex.iter().any(|regex| regex.is_match(domain))
    }

    fn matches_suffix(&self, domain: &str) -> bool {
        !self.suffix.is_empty()
            && (self.suffix.contains(domain.as_bytes())
                || domain
                    .rmatch_indices('.')
                    .any(|(index, _)| self.suffix.contains(&domain.as_bytes()[index + 1..])))
    }

    #[cfg(test)]
    pub(crate) fn name_table_heap_bytes(&self) -> usize {
        self.full.heap_bytes() + self.suffix.heap_bytes()
    }

    #[cfg(test)]
    pub(crate) fn keyword_automaton_bytes(&self) -> usize {
        self.keyword_automaton
            .as_ref()
            .map_or(0, AhoCorasick::memory_usage)
    }

    pub(crate) fn full_names(&self) -> impl Iterator<Item = &[u8]> {
        self.full.iter()
    }

    pub(crate) fn suffix_names(&self) -> impl Iterator<Item = &[u8]> {
        self.suffix.iter()
    }

    pub(crate) fn keywords(&self) -> impl Iterator<Item = &[u8]> {
        self.keywords.iter()
    }

    pub(crate) fn regex_patterns(&self) -> impl Iterator<Item = &str> {
        self.regex.iter().map(Regex::as_str)
    }
}

impl fmt::Debug for DomainPatternSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainPatternSet")
            .field("full", &self.full.len())
            .field("suffix", &self.suffix.len())
            .field("keyword", &self.keywords.len())
            .field("regex", &self.regex.len())
            .field("source_count", &self.source_count)
            .finish()
    }
}

/// Collects patterns for a [`DomainPatternSet`].
///
/// Names are copied, ASCII-lowercased, into one growing buffer per kind;
/// [`Self::build`] then deduplicates them into the packed tables. Reserving
/// the expected sizes up front keeps the collection to one allocation per
/// kind.
#[derive(Debug, Default)]
pub struct DomainPatternSetBuilder {
    full: NameList,
    suffix: NameList,
    keywords: NameList,
    regex: Vec<Regex>,
    source_count: usize,
}

impl DomainPatternSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves room for `count` `full:` names of `bytes` bytes in total.
    pub fn reserve_full(&mut self, count: usize, bytes: usize) {
        self.full.reserve(count, bytes);
    }

    /// Reserves room for `count` `domain:` suffixes of `bytes` bytes in total.
    pub fn reserve_suffix(&mut self, count: usize, bytes: usize) {
        self.suffix.reserve(count, bytes);
    }

    /// Reserves room for `count` keywords of `bytes` bytes in total.
    pub fn reserve_keyword(&mut self, count: usize, bytes: usize) {
        self.keywords.reserve(count, bytes);
    }

    pub fn reserve_regex(&mut self, count: usize) {
        self.regex.reserve_exact(count);
    }

    /// Adds one matcher; the already compiled regex of a `regexp:` matcher is
    /// shared, not recompiled.
    pub fn insert(&mut self, matcher: &DomainMatcher, mode: DomainNameMode) {
        match matcher {
            DomainMatcher::Keyword(keyword) => self.insert_keyword(keyword),
            DomainMatcher::Full(name) => self.insert_full(name, mode),
            DomainMatcher::Suffix(name) => self.insert_suffix(name, mode),
            DomainMatcher::Regex(matcher) => self.insert_regex(matcher),
        }
    }

    pub fn insert_full(&mut self, name: &str, mode: DomainNameMode) {
        self.full.push_lowercase(mode.pattern(name));
        self.source_count += 1;
    }

    pub fn insert_suffix(&mut self, name: &str, mode: DomainNameMode) {
        self.suffix.push_lowercase(mode.pattern(name));
        self.source_count += 1;
    }

    pub fn insert_keyword(&mut self, keyword: &str) {
        self.keywords.push_lowercase(keyword);
        self.source_count += 1;
    }

    pub fn insert_regex(&mut self, matcher: &RegexMatcher) {
        self.regex.push(matcher.regex().clone());
        self.source_count += 1;
    }

    /// Returns the number of patterns inserted so far, duplicates included.
    pub fn source_count(&self) -> usize {
        self.source_count
    }

    pub fn build(self) -> Result<DomainPatternSet, DomainMatcherSetError> {
        let keyword_automaton = if self.keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .kind(Some(AhoCorasickKind::ContiguousNFA))
                    .start_kind(StartKind::Unanchored)
                    .build(self.keywords.iter())?,
            )
        };
        Ok(DomainPatternSet {
            full: PackedNameTable::build(self.full)?,
            suffix: PackedNameTable::build(self.suffix)?,
            keywords: PackedStrings::build(self.keywords)?,
            keyword_automaton,
            regex: self.regex.into_boxed_slice(),
            source_count: self.source_count,
        })
    }
}

/// Names appended back to back, before deduplication.
#[derive(Debug, Default)]
struct NameList {
    bytes: Vec<u8>,
    ends: Vec<usize>,
}

impl NameList {
    fn reserve(&mut self, count: usize, bytes: usize) {
        self.ends.reserve_exact(count);
        self.bytes.reserve_exact(bytes);
    }

    fn push_lowercase(&mut self, name: &str) {
        self.bytes
            .extend(name.bytes().map(|byte| byte.to_ascii_lowercase()));
        self.ends.push(self.bytes.len());
    }

    fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    fn len(&self) -> usize {
        self.ends.len()
    }

    fn get(&self, index: usize) -> &[u8] {
        let start = index
            .checked_sub(1)
            .map_or(0, |previous| self.ends[previous]);
        &self.bytes[start..self.ends[index]]
    }

    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.len()).map(|index| self.get(index))
    }
}

/// Deduplicated names in one buffer, grouped by a keyed hash: bucket `b`
/// holds the length-prefixed names in
/// `data[buckets[b - 1].end..buckets[b].end]`.
#[derive(Clone)]
struct PackedNameTable {
    data: Box<[u8]>,
    buckets: Box<[Bucket]>,
    len: usize,
    name_bytes: usize,
    hasher: RandomState,
}

/// Where a bucket's names end, and a one-word Bloom filter of their hashes:
/// a name whose filter bit is clear is not in the bucket, so most misses
/// read this word and no name.
#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    end: u32,
    filter: u32,
}

/// Hashes the bytes alone: a table hashes nothing else, so unlike `Hash for
/// [u8]` no length prefix is needed, and short names stay one SipHash block
/// shorter.
fn hash_name(hasher: &RandomState, name: &[u8]) -> u64 {
    let mut state = hasher.build_hasher();
    state.write(name);
    state.finish()
}

/// The bucket of a hash is chosen by its low bits, its filter bit by its top
/// five.
fn filter_bit(hash: u64) -> u32 {
    1 << (hash >> 59)
}

impl PackedNameTable {
    fn build(names: NameList) -> Result<Self, DomainMatcherSetError> {
        let hasher = RandomState::new();
        if names.is_empty() {
            return Ok(Self {
                data: Box::default(),
                buckets: Box::default(),
                len: 0,
                name_bytes: 0,
                hasher,
            });
        }
        let bucket_count = (names.len() / NAMES_PER_BUCKET).max(1).next_power_of_two();
        let mask = bucket_count - 1;
        let too_large = || DomainMatcherSetError::TooLarge {
            names: names.len(),
            bytes: names.bytes.len(),
        };
        let mut order = Vec::with_capacity(names.len());
        for index in 0..names.len() {
            let bucket = hash_name(&hasher, names.get(index)) as usize & mask;
            order.push((
                u32::try_from(bucket).map_err(|_| too_large())?,
                u32::try_from(index).map_err(|_| too_large())?,
            ));
        }
        let name = |entry: &(u32, u32)| names.get(entry.1 as usize);
        order.sort_unstable_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| name(left).cmp(name(right)))
        });
        order.dedup_by(|later, earlier| later.0 == earlier.0 && name(later) == name(earlier));

        let data_len = order
            .iter()
            .map(|entry| {
                let len = name(entry).len();
                len_prefix_size(len) + len
            })
            .sum::<usize>();
        if u32::try_from(data_len).is_err() {
            return Err(too_large());
        }
        let mut data = Vec::with_capacity(data_len);
        let mut buckets = Vec::with_capacity(bucket_count);
        let mut name_bytes = 0;
        let mut entries = order.iter().peekable();
        for bucket in 0..bucket_count {
            let mut filter = 0;
            while let Some(entry) = entries.next_if(|entry| entry.0 as usize == bucket) {
                let bytes = name(entry);
                filter |= filter_bit(hash_name(&hasher, bytes));
                push_len_prefix(&mut data, bytes.len());
                data.extend_from_slice(bytes);
                name_bytes += bytes.len();
            }
            buckets.push(Bucket {
                // Bounded by `data_len`, checked above.
                end: data.len() as u32,
                filter,
            });
        }
        debug_assert_eq!(data.len(), data_len);
        Ok(Self {
            data: data.into_boxed_slice(),
            buckets: buckets.into_boxed_slice(),
            len: order.len(),
            name_bytes,
            hasher,
        })
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn name_bytes(&self) -> usize {
        self.name_bytes
    }

    fn heap_bytes(&self) -> usize {
        self.data.len() + size_of_val(self.buckets.as_ref())
    }

    fn contains(&self, name: &[u8]) -> bool {
        if self.len == 0 {
            return false;
        }
        let hash = hash_name(&self.hasher, name);
        let bucket = hash as usize & (self.buckets.len() - 1);
        let Bucket { end, filter } = self.buckets[bucket];
        if filter & filter_bit(hash) == 0 {
            return false;
        }
        let start = bucket
            .checked_sub(1)
            .map_or(0, |previous| self.buckets[previous].end as usize);
        PackedNames::new(&self.data[start..end as usize]).any(|candidate| candidate == name)
    }

    fn iter(&self) -> PackedNames<'_> {
        PackedNames::new(&self.data)
    }
}

/// Strings in one buffer with an end offset each, in insertion order.
#[derive(Clone, Default)]
struct PackedStrings {
    bytes: Box<[u8]>,
    ends: Box<[u32]>,
}

impl PackedStrings {
    fn build(list: NameList) -> Result<Self, DomainMatcherSetError> {
        let too_large = || DomainMatcherSetError::TooLarge {
            names: list.len(),
            bytes: list.bytes.len(),
        };
        let ends = list
            .ends
            .iter()
            .map(|end| u32::try_from(*end).map_err(|_| too_large()))
            .collect::<Result<Box<[u32]>, _>>()?;
        Ok(Self {
            bytes: list.bytes.into_boxed_slice(),
            ends,
        })
    }

    fn len(&self) -> usize {
        self.ends.len()
    }

    fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    fn heap_bytes(&self) -> usize {
        self.bytes.len() + self.ends.len() * size_of::<u32>()
    }

    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let mut start = 0;
        self.ends.iter().map(move |end| {
            let name = &self.bytes[start..*end as usize];
            start = *end as usize;
            name
        })
    }
}

/// Iterates length-prefixed names written by [`push_len_prefix`].
struct PackedNames<'a> {
    data: &'a [u8],
}

impl<'a> PackedNames<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for PackedNames<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let mut len = 0usize;
        let mut shift = 0;
        let mut consumed = 0;
        for byte in self.data {
            consumed += 1;
            len |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let (name, rest) = self.data[consumed..].split_at(len);
        self.data = rest;
        Some(name)
    }
}

fn push_len_prefix(output: &mut Vec<u8>, mut len: usize) {
    while len >= 0x80 {
        output.push(len as u8 | 0x80);
        len >>= 7;
    }
    output.push(len as u8);
}

fn len_prefix_size(len: usize) -> usize {
    let bits = usize::BITS - len.leading_zeros();
    bits.div_ceil(7).max(1) as usize
}

pub(crate) fn lowercase_ascii(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(full: &[&str], suffix: &[&str], keyword: &[&str], regex: &[&str]) -> DomainPatternSet {
        let mut builder = DomainPatternSet::builder();
        for name in full {
            builder.insert_full(name, DomainNameMode::Routing);
        }
        for name in suffix {
            builder.insert_suffix(name, DomainNameMode::Routing);
        }
        for keyword in keyword {
            builder.insert_keyword(keyword);
        }
        for pattern in regex {
            builder.insert_regex(&RegexMatcher::new(*pattern).unwrap());
        }
        builder.build().unwrap()
    }

    #[test]
    fn length_prefixes_round_trip_across_varint_widths() {
        for len in [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 70_000] {
            let mut data = Vec::new();
            push_len_prefix(&mut data, len);
            assert_eq!(data.len(), len_prefix_size(len), "len {len}");
            data.extend(std::iter::repeat_n(b'a', len));
            push_len_prefix(&mut data, 1);
            data.push(b'z');
            let names = PackedNames::new(&data).collect::<Vec<_>>();
            assert_eq!(names.len(), 2);
            assert_eq!(names[0].len(), len);
            assert_eq!(names[1], b"z");
        }
    }

    #[test]
    fn packed_tables_deduplicate_and_find_every_name() {
        let names = (0..5_000)
            .map(|index| format!("Host-{index}.Example"))
            .collect::<Vec<_>>();
        let mut builder = DomainPatternSet::builder();
        for name in names.iter().chain(names.iter().take(100)) {
            builder.insert_full(name, DomainNameMode::Routing);
        }
        builder.insert_full(&"x".repeat(300), DomainNameMode::Routing);
        let set = builder.build().unwrap();

        assert_eq!(set.source_count(), 5_101);
        assert_eq!(set.full_count(), 5_001);
        assert_eq!(
            set.pattern_bytes(),
            names.iter().map(String::len).sum::<usize>() + 300
        );
        for name in &names {
            assert!(set.matches(name), "{name}");
            assert!(set.matches(&name.to_ascii_uppercase()), "{name}");
            assert!(!set.matches(&format!("www.{name}")), "{name}");
        }
        assert!(set.matches(&"X".repeat(300)));
        assert!(!set.matches(&"x".repeat(299)));
        assert!(!set.matches("host-5000.example"));
        assert_eq!(set.full_names().count(), 5_001);
    }

    #[test]
    fn suffixes_keywords_and_regexes_follow_the_matcher_semantics() {
        let set = build(
            &["Exact.TEST", "dotted.test."],
            &["Example.com", "corp", ".lead.test", ""],
            &["Kw-X", "zz"],
            &[r"^api\.[a-z]+\.test$"],
        );
        assert_eq!(set.source_count(), 9);
        assert!(set.matches("exact.test"));
        assert!(!set.matches("www.exact.test"));
        assert!(set.matches("dotted.test."));
        assert!(!set.matches("dotted.test"));
        assert!(set.matches("a.b.EXAMPLE.com"));
        assert!(!set.matches("notexample.com"));
        assert!(set.matches("intranet.corp"));
        assert!(set.matches("x..lead.test"));
        assert!(!set.matches("www.lead.test"));
        assert!(set.matches("trailing.dot."));
        assert!(set.matches(""));
        assert!(set.matches("a-KW-x-b"));
        assert!(set.matches("buzz.invalid"));
        assert!(set.matches("API.svc.test"));
        assert!(!set.matches("other.invalid"));
        assert_eq!(set.keywords().collect::<Vec<_>>(), [&b"kw-x"[..], b"zz"]);
        assert_eq!(
            set.regex_patterns().collect::<Vec<_>>(),
            [r"^api\.[a-z]+\.test$"]
        );
    }

    #[test]
    fn dns_mode_trims_trailing_dots_from_full_and_suffix_names() {
        let mut builder = DomainPatternSet::builder();
        builder.insert_full("dotted.test.", DomainNameMode::Dns);
        builder.insert_suffix("trailing.example..", DomainNameMode::Dns);
        let set = builder.build().unwrap();
        assert!(set.matches("dotted.test"));
        assert!(!set.matches("dotted.test."));
        assert!(set.matches("a.trailing.example"));
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = DomainPatternSet::builder().build().unwrap();
        assert!(set.is_empty());
        assert!(!set.matches(""));
        assert!(!set.matches("example.com"));
        assert_eq!(set.pattern_bytes(), 0);
        assert_eq!(set.heap_size_estimate(), 0);
    }

    #[test]
    fn packed_names_cost_less_than_one_allocation_per_name() {
        let mut builder = DomainPatternSet::builder();
        let mut name_bytes = 0;
        for index in 0..73_515 {
            let name = format!("blocked-{index}.example");
            name_bytes += name.len();
            builder.insert_suffix(&name, DomainNameMode::Routing);
        }
        let set = builder.build().unwrap();
        let heap = set.heap_size_estimate();
        eprintln!("73515 suffixes: {name_bytes} name bytes, {heap} heap bytes");
        // One length byte per name plus at most two eight-byte buckets per
        // `NAMES_PER_BUCKET` names.
        assert!(heap <= name_bytes + 73_515 + 73_515 * 2 * 8 / NAMES_PER_BUCKET);
        assert!(set.matches("www.blocked-73514.example"));
        assert!(!set.matches("blocked-73515.example"));
    }
}
