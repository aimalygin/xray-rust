use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use crate::domain_pattern_set::{lowercase_ascii, DomainPatternSet, DomainPatternSetBuilder};
use crate::{DomainMatcher, DomainNameMode};

/// Small routing rules are more common than geosite-sized matcher sets. A
/// linear scan avoids a hash lookup (and an ASCII-case normalization pass) for
/// each rule while the indexed representation still handles large sets.
const LINEAR_MATCHER_LIMIT: usize = 8;

/// Query-ready set of `full:`, `domain:`, `keyword:` and `regexp:` matchers
/// belonging to one rule.
///
/// Names are matched per label and ASCII case-insensitively: `domain:a.test`
/// matches `a.test` and `b.a.test` but not `ba.test`. Trailing dots are kept
/// as-is on both sides, so DNS callers normalize names before matching.
///
/// A set holds the rule's own matchers, scanned linearly when there are at
/// most a few of them and packed into a [`DomainPatternSet`] otherwise, plus
/// any number of already compiled [`DomainPatternSet`]s inserted with
/// [`DomainMatcherSetBuilder::insert_shared`]: geodata categories that other
/// rules and cores share instead of copying.
///
/// The compiled state is immutable and shared behind an `Arc`, so cloning a
/// set only bumps a reference count instead of copying its tables, automaton
/// and regexes.
#[derive(Clone, Default)]
pub struct DomainMatcherSet {
    inner: Option<Arc<DomainMatcherSetInner>>,
    matcher_count: usize,
}

struct DomainMatcherSetInner {
    /// At most [`LINEAR_MATCHER_LIMIT`] rule-local matchers, normalized.
    linear: Box<[DomainMatcher]>,
    /// Rule-local matchers above the linear limit.
    patterns: Option<DomainPatternSet>,
    /// Compiled sets shared with other rules and cores.
    shared: Box<[Arc<DomainPatternSet>]>,
}

impl DomainMatcherSet {
    pub fn builder() -> DomainMatcherSetBuilder {
        DomainMatcherSetBuilder::default()
    }

    /// Compiles `matchers` in one pass; `mode` picks the `full:`/`domain:`
    /// pattern normalization.
    pub fn compile(
        matchers: &[DomainMatcher],
        mode: DomainNameMode,
    ) -> Result<Self, DomainMatcherSetError> {
        let mut builder = Self::builder();
        for matcher in matchers {
            builder.insert(matcher, mode);
        }
        builder.build()
    }

    pub fn is_empty(&self) -> bool {
        self.matcher_count == 0
    }

    /// Returns the number of source matchers inserted, duplicates included.
    /// A shared set counts its own source patterns.
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    /// Returns the retained pattern payload in bytes, excluding table,
    /// automaton and regex-engine overhead. Shared sets count in full.
    pub fn pattern_bytes(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.pattern_bytes())
    }

    /// The compiled sets inserted with
    /// [`DomainMatcherSetBuilder::insert_shared`], without duplicates.
    pub fn shared_sets(&self) -> &[Arc<DomainPatternSet>] {
        self.inner.as_ref().map_or(&[], |inner| &inner.shared)
    }

    pub fn matches(&self, domain: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        if inner.linear.iter().any(|matcher| matcher.matches(domain)) {
            return true;
        }
        if inner.patterns.is_none() && inner.shared.is_empty() {
            return false;
        }
        let domain = lowercase_ascii(domain);
        inner
            .patterns
            .as_ref()
            .is_some_and(|patterns| patterns.matches_lowercase(&domain))
            || inner
                .shared
                .iter()
                .any(|patterns| patterns.matches_lowercase(&domain))
    }
}

impl DomainMatcherSetInner {
    fn pattern_sets(&self) -> impl Iterator<Item = &DomainPatternSet> {
        self.patterns
            .iter()
            .chain(self.shared.iter().map(|patterns| patterns.as_ref()))
    }

    fn pattern_bytes(&self) -> usize {
        self.linear.iter().map(matcher_pattern_bytes).sum::<usize>()
            + self
                .pattern_sets()
                .map(DomainPatternSet::pattern_bytes)
                .sum::<usize>()
    }

    /// Distinct `full`, `suffix`, `keyword` and `regex` patterns per stored
    /// table, as `Debug` reports them.
    fn kind_counts(&self) -> [usize; 4] {
        let mut counts = [0; 4];
        for matcher in self.linear.iter() {
            counts[match matcher {
                DomainMatcher::Full(_) => 0,
                DomainMatcher::Suffix(_) => 1,
                DomainMatcher::Keyword(_) => 2,
                DomainMatcher::Regex(_) => 3,
            }] += 1;
        }
        for patterns in self.pattern_sets() {
            counts[0] += patterns.full_count();
            counts[1] += patterns.suffix_count();
            counts[2] += patterns.keyword_count();
            counts[3] += patterns.regex_count();
        }
        counts
    }

    /// Every normalized pattern, sorted and deduplicated per kind, whichever
    /// table holds it.
    fn summary(&self) -> PatternSummary<'_> {
        let mut summary = PatternSummary::default();
        for matcher in self.linear.iter() {
            match matcher {
                DomainMatcher::Full(name) => summary.full.push(name.as_bytes()),
                DomainMatcher::Suffix(name) => summary.suffix.push(name.as_bytes()),
                DomainMatcher::Keyword(keyword) => summary.keywords.push(keyword.as_bytes()),
                DomainMatcher::Regex(matcher) => summary.regex.push(matcher.pattern()),
            }
        }
        for patterns in self.pattern_sets() {
            summary.full.extend(patterns.full_names());
            summary.suffix.extend(patterns.suffix_names());
            summary.keywords.extend(patterns.keywords());
            summary.regex.extend(patterns.regex_patterns());
        }
        for names in [
            &mut summary.full,
            &mut summary.suffix,
            &mut summary.keywords,
        ] {
            names.sort_unstable();
            names.dedup();
        }
        summary.regex.sort_unstable();
        summary.regex.dedup();
        summary
    }
}

#[derive(Default, PartialEq, Eq)]
struct PatternSummary<'a> {
    full: Vec<&'a [u8]>,
    suffix: Vec<&'a [u8]>,
    keywords: Vec<&'a [u8]>,
    regex: Vec<&'a str>,
}

impl fmt::Debug for DomainMatcherSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [full, suffix, keyword, regex] = self
            .inner
            .as_ref()
            .map_or([0; 4], |inner| inner.kind_counts());
        f.debug_struct("DomainMatcherSet")
            .field("full", &full)
            .field("suffix", &suffix)
            .field("keyword", &keyword)
            .field("regex", &regex)
            .field("matcher_count", &self.matcher_count)
            .finish()
    }
}

/// Two sets are equal when they hold the same number of source matchers and
/// the same normalized patterns, however the patterns are stored: a geodata
/// category inserted as a shared set equals the same names inserted one by
/// one.
impl PartialEq for DomainMatcherSet {
    fn eq(&self, other: &Self) -> bool {
        self.matcher_count == other.matcher_count
            && match (&self.inner, &other.inner) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a.summary() == b.summary(),
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl Eq for DomainMatcherSet {}

#[derive(Debug, Error)]
pub enum DomainMatcherSetError {
    #[error("keyword matchers exceed the automaton limits: {0}")]
    Keyword(#[from] aho_corasick::BuildError),
    #[error("{names} domain patterns of {bytes} bytes exceed the packed table limits")]
    TooLarge { names: usize, bytes: usize },
}

#[derive(Debug, Default)]
pub struct DomainMatcherSetBuilder {
    /// The rule-local matchers while there are at most
    /// [`LINEAR_MATCHER_LIMIT`]; `None` once there are more.
    linear: Option<Vec<DomainMatcher>>,
    patterns: DomainPatternSetBuilder,
    shared: Vec<Arc<DomainPatternSet>>,
    matcher_count: usize,
}

impl DomainMatcherSetBuilder {
    /// Adds one matcher; the already compiled regex of a `regexp:` matcher is
    /// shared, not recompiled.
    pub fn insert(&mut self, matcher: &DomainMatcher, mode: DomainNameMode) {
        if self.patterns.source_count() < LINEAR_MATCHER_LIMIT {
            let linear = self.linear.get_or_insert_with(Vec::new);
            let matcher = normalize_linear_matcher(matcher, mode);
            if !linear.contains(&matcher) {
                linear.push(matcher);
            }
        } else {
            self.linear = None;
        }
        self.patterns.insert(matcher, mode);
        self.matcher_count += 1;
    }

    /// Adds an already compiled set, such as a geodata category, by
    /// reference: matching consults it as it is, and its source patterns count
    /// toward [`Self::matcher_count`]. Inserting the same set again only adds
    /// to the count.
    pub fn insert_shared(&mut self, patterns: &Arc<DomainPatternSet>) {
        self.matcher_count += patterns.source_count();
        if patterns.is_empty()
            || self
                .shared
                .iter()
                .any(|existing| Arc::ptr_eq(existing, patterns))
        {
            return;
        }
        self.shared.push(Arc::clone(patterns));
    }

    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    pub fn build(self) -> Result<DomainMatcherSet, DomainMatcherSetError> {
        if self.matcher_count == 0 {
            return Ok(DomainMatcherSet::default());
        }
        let matcher_count = self.matcher_count;
        let (linear, patterns) = match self.linear {
            _ if self.patterns.source_count() == 0 => (Box::default(), None),
            Some(linear) => (linear.into_boxed_slice(), None),
            None => (Box::default(), Some(self.patterns.build()?)),
        };
        Ok(DomainMatcherSet {
            inner: Some(Arc::new(DomainMatcherSetInner {
                linear,
                patterns,
                shared: self.shared.into_boxed_slice(),
            })),
            matcher_count,
        })
    }
}

fn normalize_linear_matcher(matcher: &DomainMatcher, mode: DomainNameMode) -> DomainMatcher {
    match matcher {
        DomainMatcher::Keyword(keyword) => DomainMatcher::Keyword(keyword.to_ascii_lowercase()),
        DomainMatcher::Full(domain) => {
            DomainMatcher::Full(mode.pattern(domain).to_ascii_lowercase())
        }
        DomainMatcher::Suffix(suffix) => {
            DomainMatcher::Suffix(mode.pattern(suffix).to_ascii_lowercase())
        }
        DomainMatcher::Regex(matcher) => DomainMatcher::Regex(matcher.clone()),
    }
}

fn matcher_pattern_bytes(matcher: &DomainMatcher) -> usize {
    match matcher {
        DomainMatcher::Keyword(pattern)
        | DomainMatcher::Full(pattern)
        | DomainMatcher::Suffix(pattern) => pattern.len(),
        DomainMatcher::Regex(matcher) => matcher.pattern().len(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::mem::size_of;

    use super::*;
    use crate::RegexMatcher;

    fn matchers(
        full: &[&str],
        suffix: &[&str],
        keyword: &[&str],
        regex: &[&str],
    ) -> Vec<DomainMatcher> {
        full.iter()
            .map(|name| DomainMatcher::Full((*name).to_owned()))
            .chain(
                suffix
                    .iter()
                    .map(|name| DomainMatcher::Suffix((*name).to_owned())),
            )
            .chain(
                keyword
                    .iter()
                    .map(|name| DomainMatcher::Keyword((*name).to_owned())),
            )
            .chain(
                regex
                    .iter()
                    .map(|pattern| DomainMatcher::Regex(RegexMatcher::new(*pattern).unwrap())),
            )
            .collect()
    }

    fn compile(
        full: &[&str],
        suffix: &[&str],
        keyword: &[&str],
        regex: &[&str],
    ) -> DomainMatcherSet {
        DomainMatcherSet::compile(
            &matchers(full, suffix, keyword, regex),
            DomainNameMode::Routing,
        )
        .unwrap()
    }

    /// The bytes a `HashSet<Box<str>>` of the same names would hold, the
    /// representation before the packed tables: its slots plus one heap
    /// allocation per name, rounded to the 16-byte allocator quantum.
    fn boxed_hash_set_bytes(names: usize, name_bytes: usize) -> usize {
        let buckets = (names * 8).div_ceil(7).next_power_of_two();
        buckets * (size_of::<Box<str>>() + 1) + name_bytes + names * 8
    }

    fn shared(full: &[&str], suffix: &[&str]) -> Arc<DomainPatternSet> {
        let mut builder = DomainPatternSet::builder();
        for name in full {
            builder.insert_full(name, DomainNameMode::Routing);
        }
        for name in suffix {
            builder.insert_suffix(name, DomainNameMode::Routing);
        }
        Arc::new(builder.build().unwrap())
    }

    #[test]
    fn clone_shares_compiled_state() {
        let set = compile(&["a.test"], &[], &[], &[]);
        let cloned = set.clone();
        assert!(Arc::ptr_eq(
            set.inner.as_ref().unwrap(),
            cloned.inner.as_ref().unwrap()
        ));
        assert_eq!(cloned, set);
        assert!(cloned.matches("a.test"));
    }

    #[test]
    fn small_sets_use_the_linear_fast_path_without_retaining_indexes() {
        let set = compile(&["a.test", "b.test"], &["suffix.test"], &["kw"], &["^rx$"]);
        let inner = set.inner.as_deref().unwrap();

        assert_eq!(inner.linear.len(), 5);
        assert!(inner.patterns.is_none());
        assert!(inner.shared.is_empty());
        assert!(set.matches("B.TEST"));
        assert!(set.matches("deep.SUFFIX.test"));
        assert!(set.matches("prefix-KW-suffix"));
        assert!(set.matches("RX"));
    }

    #[test]
    fn sets_above_the_linear_limit_use_the_compiled_indexes() {
        let full = (0..=LINEAR_MATCHER_LIMIT)
            .map(|index| format!("host-{index}.test"))
            .collect::<Vec<_>>();
        let matchers = full
            .iter()
            .map(|name| DomainMatcher::Full(name.clone()))
            .collect::<Vec<_>>();
        let set = DomainMatcherSet::compile(&matchers, DomainNameMode::Routing).unwrap();
        let inner = set.inner.as_deref().unwrap();

        assert!(inner.linear.is_empty());
        assert_eq!(
            inner.patterns.as_ref().unwrap().full_count(),
            LINEAR_MATCHER_LIMIT + 1
        );
        assert!(set.matches("HOST-8.TEST"));
        assert!(!set.matches("missing.test"));
    }

    #[test]
    fn empty_set_matches_nothing_and_reports_zero_sizes() {
        let empty = DomainMatcherSet::default();
        assert!(empty.is_empty());
        assert_eq!(empty.matcher_count(), 0);
        assert_eq!(empty.pattern_bytes(), 0);
        assert!(!empty.matches(""));
        assert!(!empty.matches("example.com"));
        assert_eq!(DomainMatcherSet::builder().build().unwrap(), empty);
        assert_eq!(
            format!("{empty:?}"),
            "DomainMatcherSet { full: 0, suffix: 0, keyword: 0, regex: 0, matcher_count: 0 }"
        );
    }

    #[test]
    fn full_names_match_exactly_and_case_insensitively() {
        let set = compile(&["Example.COM", "exact.test."], &[], &[], &[]);
        assert_eq!(set.matcher_count(), 2);
        assert!(set.matches("example.com"));
        assert!(set.matches("EXAMPLE.com"));
        assert!(!set.matches("www.example.com"));
        assert!(!set.matches("example.com."));
        assert!(set.matches("exact.test."));
        assert!(!set.matches("exact.test"));
        assert!(!set.matches("notexample.com"));
    }

    #[test]
    fn suffixes_match_on_label_boundaries_only() {
        let set = compile(&[], &["Example.com", "corp", ".lead.test", ""], &[], &[]);
        assert!(set.matches("example.com"));
        assert!(set.matches("a.b.EXAMPLE.com"));
        assert!(!set.matches("notexample.com"));
        assert!(!set.matches("example.com.evil"));
        assert!(set.matches("corp"));
        assert!(set.matches("intranet.corp"));
        assert!(!set.matches("corp.example"));
        assert!(set.matches(".lead.test"));
        assert!(set.matches("x..lead.test"));
        assert!(!set.matches("www.lead.test"));
        assert!(set.matches(""));
        assert!(set.matches("trailing.dot."));
        assert!(!set.matches("nodot"));
    }

    #[test]
    fn full_and_suffix_rules_for_the_same_name_are_kept_apart() {
        let set = compile(&["shared.test"], &["shared.test"], &[], &[]);
        assert_eq!(set.matcher_count(), 2);
        assert!(set.matches("shared.test"));
        assert!(set.matches("deep.shared.test"));

        let full_only = compile(&["only.test"], &[], &[], &[]);
        assert!(!full_only.matches("deep.only.test"));

        let duplicated = compile(&["dup.test", "DUP.test"], &[], &[], &[]);
        assert_eq!(duplicated.matcher_count(), 2);
        assert_eq!(duplicated.pattern_bytes(), "dup.test".len());
    }

    #[test]
    fn keywords_match_anywhere_case_insensitively_including_empty() {
        let set = compile(&[], &[], &["Ample", "zz"], &[]);
        assert!(set.matches("EXAMPLE.com"));
        assert!(set.matches("sample"));
        assert!(set.matches("buzz.test"));
        assert!(!set.matches("other.test"));
        assert!(!set.matches(""));

        let empty_keyword = compile(&[], &[], &[""], &[]);
        assert!(empty_keyword.matches(""));
        assert!(empty_keyword.matches("anything"));
    }

    #[test]
    fn regexes_match_the_lowercased_name() {
        let set = compile(
            &[],
            &[],
            &[],
            &[r"^[^.]*local[^.]*$", r"^api\.[a-z]+\.test$"],
        );
        assert!(set.matches("MyLocalHost"));
        assert!(!set.matches("local.host"));
        assert!(set.matches("API.svc.test"));
        assert!(!set.matches("api.svc.test."));
    }

    #[test]
    fn dns_mode_trims_trailing_dots_from_full_and_suffix_patterns() {
        let matchers = matchers(&["dotted.test."], &["trailing.example."], &[], &[]);
        let routing = DomainMatcherSet::compile(&matchers, DomainNameMode::Routing).unwrap();
        let dns = DomainMatcherSet::compile(&matchers, DomainNameMode::Dns).unwrap();

        assert!(routing.matches("dotted.test."));
        assert!(!routing.matches("dotted.test"));
        assert!(routing.matches("a.trailing.example."));
        assert!(!routing.matches("a.trailing.example"));

        assert!(dns.matches("dotted.test"));
        assert!(!dns.matches("dotted.test."));
        assert!(dns.matches("a.trailing.example"));
        assert!(!dns.matches("a.trailing.example."));
        assert_eq!(dns.matcher_count(), 2);
    }

    #[test]
    fn regex_matchers_share_the_prevalidated_regex() {
        let matcher = RegexMatcher::new(r"^cdn[0-9]+\.example$").unwrap();
        let mut builder = DomainMatcherSet::builder();
        builder.insert(
            &DomainMatcher::Regex(matcher.clone()),
            DomainNameMode::Routing,
        );
        let set = builder.build().unwrap();
        assert_eq!(set.matcher_count(), 1);
        assert_eq!(set.pattern_bytes(), matcher.pattern().len());
        assert!(set.matches("CDN7.example"));
        assert!(!set.matches("cdn.example"));
    }

    #[test]
    fn equality_debug_and_pattern_bytes_cover_all_kinds() {
        let left = compile(&["a.test"], &["b.test"], &["kw"], &["^c$"]);
        let right = compile(&["A.TEST"], &["B.test"], &["KW"], &["^c$"]);
        assert_eq!(left, right);
        assert_ne!(left, compile(&["a.test"], &["b.test"], &["kw"], &["^d$"]));
        assert_ne!(left, compile(&["a.test"], &["b.test"], &[], &["^c$"]));
        assert_ne!(
            left,
            compile(&["a.test", "a.test"], &["b.test"], &["kw"], &["^c$"])
        );
        assert_eq!(left.pattern_bytes(), 6 + 6 + 2 + 3);
        assert_eq!(
            format!("{left:?}"),
            "DomainMatcherSet { full: 1, suffix: 1, keyword: 1, regex: 1, matcher_count: 4 }"
        );
        let cloned = left.clone();
        assert!(cloned.matches("x.b.test") && cloned.matches("c") && cloned.matches("akwz"));
    }

    #[test]
    fn geosite_sized_mix_stays_within_the_memory_budget() {
        let mut builder = DomainMatcherSet::builder();
        for index in 0..100_000 {
            builder.insert(
                &DomainMatcher::Suffix(format!("site-{index}.geosite-suffix.example")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..20_000 {
            builder.insert(
                &DomainMatcher::Full(format!("host-{index}.geosite-full.example")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..2_000 {
            builder.insert(
                &DomainMatcher::Keyword(format!("keyword-{index:04}")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..200 {
            builder.insert(
                &DomainMatcher::Regex(
                    RegexMatcher::new(format!(r"^ad[0-9]*-{index}\.[a-z]+\.example$")).unwrap(),
                ),
                DomainNameMode::Routing,
            );
        }
        let set = builder.build().unwrap();
        assert_eq!(set.matcher_count(), 122_200);
        let patterns = set.inner.as_deref().unwrap().patterns.as_ref().unwrap();

        let names = patterns.full_count() + patterns.suffix_count();
        let name_bytes = patterns
            .full_names()
            .chain(patterns.suffix_names())
            .map(<[u8]>::len)
            .sum::<usize>();
        let name_table_bytes = patterns.name_table_heap_bytes();
        let automaton_bytes = patterns.keyword_automaton_bytes();
        let boxed_bytes = boxed_hash_set_bytes(names, name_bytes);
        eprintln!(
            "names: {names} names of {name_bytes} B in packed tables of {name_table_bytes} B (boxed hash sets: {boxed_bytes} B); keyword automaton {automaton_bytes} B"
        );

        assert_eq!(names, 120_000);
        // A length byte per name plus at most eight bytes of buckets each.
        assert!(name_table_bytes <= name_bytes + names + names * 8);
        assert!(name_table_bytes * 2 <= boxed_bytes);
        assert!(automaton_bytes <= 1024 * 1024);

        assert!(set.matches("www.site-77777.geosite-suffix.example"));
        assert!(set.matches("host-19999.geosite-full.example"));
        assert!(!set.matches("www.host-19999.geosite-full.example"));
        assert!(set.matches("cdn.keyword-1999.test"));
        assert!(set.matches("ad42-199.tracker.example"));
        assert!(!set.matches("clean.example"));
    }

    #[test]
    fn shared_sets_are_consulted_by_reference() {
        let category = shared(&["exact.example"], &["blocked.example", "other.example"]);
        let mut builder = DomainMatcherSet::builder();
        builder.insert(
            &DomainMatcher::Full("local.test".to_owned()),
            DomainNameMode::Routing,
        );
        builder.insert_shared(&category);
        builder.insert_shared(&category);
        let set = builder.build().unwrap();

        assert_eq!(set.matcher_count(), 7);
        assert_eq!(set.shared_sets().len(), 1);
        assert!(Arc::ptr_eq(&set.shared_sets()[0], &category));
        assert_eq!(Arc::strong_count(&category), 2);
        assert!(set.matches("local.test"));
        assert!(set.matches("EXACT.example"));
        assert!(!set.matches("www.exact.example"));
        assert!(set.matches("www.Blocked.example"));
        assert!(!set.matches("unblocked.example"));
        assert_eq!(
            set.pattern_bytes(),
            "local.test".len()
                + "exact.example".len()
                + "blocked.example".len()
                + "other.example".len()
        );
        assert_eq!(
            format!("{set:?}"),
            "DomainMatcherSet { full: 2, suffix: 2, keyword: 0, regex: 0, matcher_count: 7 }"
        );

        drop(set);
        assert_eq!(Arc::strong_count(&category), 1);
    }

    #[test]
    fn empty_shared_sets_add_nothing() {
        let mut builder = DomainMatcherSet::builder();
        builder.insert_shared(&shared(&[], &[]));
        let set = builder.build().unwrap();
        assert_eq!(set, DomainMatcherSet::default());
        assert!(set.shared_sets().is_empty());
        assert!(!set.matches(""));

        let mut builder = DomainMatcherSet::builder();
        builder.insert_shared(&shared(&[], &["only.example"]));
        let set = builder.build().unwrap();
        assert!(set.inner.as_ref().unwrap().patterns.is_none());
        assert!(set.matches("a.only.example"));
    }

    #[test]
    fn sets_compare_by_patterns_whichever_table_holds_them() {
        let names = (0..20)
            .map(|index| format!("host-{index}.example"))
            .collect::<Vec<_>>();
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        let local = compile(&[], &names, &[], &[]);
        let mut builder = DomainMatcherSet::builder();
        builder.insert_shared(&shared(&[], &names));
        let from_shared = builder.build().unwrap();
        assert_eq!(from_shared, local);
        assert_ne!(from_shared, compile(&names, &[], &[], &[]));

        let small = compile(&["a.test"], &["b.test"], &[], &[]);
        let mut builder = DomainMatcherSet::builder();
        builder.insert_shared(&shared(&["A.TEST"], &["b.test"]));
        assert_eq!(builder.build().unwrap(), small);
    }

    #[test]
    fn mixed_sets_match_like_the_linear_reference() {
        let category = shared(
            &["exact.example", "Upper.Example"],
            &["blocked.example", "", "corp"],
        );
        let local = matchers(
            &["one.test"],
            &["two.test"],
            &["kw"],
            &[r"^rx[0-9]+\.test$"],
        );
        let mut builder = DomainMatcherSet::builder();
        for matcher in &local {
            builder.insert(matcher, DomainNameMode::Routing);
        }
        builder.insert_shared(&category);
        let set = builder.build().unwrap();

        let reference = local
            .iter()
            .cloned()
            .chain(
                ["exact.example", "Upper.Example"].map(|name| DomainMatcher::Full(name.to_owned())),
            )
            .chain(
                ["blocked.example", "", "corp"].map(|name| DomainMatcher::Suffix(name.to_owned())),
            )
            .collect::<Vec<_>>();
        let unique = HashSet::<&str>::from_iter([
            "",
            ".",
            "one.test",
            "x.one.test",
            "two.test",
            "a.two.test",
            "akwb",
            "rx7.test",
            "RX7.TEST",
            "rx.test",
            "exact.example",
            "a.exact.example",
            "upper.example",
            "blocked.example",
            "deep.Blocked.EXAMPLE",
            "notblocked.example",
            "corp",
            "intranet.corp",
            "corp.example",
            "trailing.",
            "plain",
        ]);
        for name in unique {
            assert_eq!(
                set.matches(name),
                reference.iter().any(|matcher| matcher.matches(name)),
                "{name}"
            );
        }
    }
}
