use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickKind, StartKind};
use regex::Regex;
use thiserror::Error;

use crate::{DomainMatcher, DomainNameMode};

/// Query-ready set of `full:`, `domain:`, `keyword:` and `regexp:` matchers
/// belonging to one rule.
///
/// Names are matched per label and ASCII case-insensitively: `domain:a.test`
/// matches `a.test` and `b.a.test` but not `ba.test`. Trailing dots are kept
/// as-is on both sides, so DNS callers normalize names before matching.
#[derive(Clone, Default)]
pub struct DomainMatcherSet {
    inner: Option<Box<DomainMatcherSetInner>>,
    matcher_count: usize,
}

#[derive(Clone)]
struct DomainMatcherSetInner {
    full: HashSet<Box<str>>,
    suffix: HashSet<Box<str>>,
    keywords: Vec<Box<str>>,
    keyword_automaton: Option<AhoCorasick>,
    regex: Vec<Regex>,
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
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    /// Returns the retained pattern payload in bytes, excluding hash-table,
    /// automaton and regex-engine overhead.
    pub fn pattern_bytes(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.pattern_bytes())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        let domain = lowercase_ascii(domain);
        inner.full.contains(domain.as_ref())
            || inner.matches_suffix(&domain)
            || inner.matches_keyword(&domain)
            || inner.matches_regex(&domain)
    }
}

impl DomainMatcherSetInner {
    fn pattern_bytes(&self) -> usize {
        self.full.iter().map(|name| name.len()).sum::<usize>()
            + self.suffix.iter().map(|name| name.len()).sum::<usize>()
            + self
                .keywords
                .iter()
                .map(|keyword| keyword.len())
                .sum::<usize>()
            + self
                .regex
                .iter()
                .map(|regex| regex.as_str().len())
                .sum::<usize>()
    }

    fn matches_suffix(&self, domain: &str) -> bool {
        !self.suffix.is_empty()
            && (self.suffix.contains(domain)
                || domain
                    .rmatch_indices('.')
                    .any(|(index, _)| self.suffix.contains(&domain[index + 1..])))
    }

    fn matches_keyword(&self, domain: &str) -> bool {
        self.keyword_automaton
            .as_ref()
            .is_some_and(|automaton| automaton.is_match(domain))
    }

    fn matches_regex(&self, domain: &str) -> bool {
        self.regex.iter().any(|regex| regex.is_match(domain))
    }
}

impl fmt::Debug for DomainMatcherSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let counts = |select: fn(&DomainMatcherSetInner) -> usize| {
            self.inner.as_ref().map_or(0, |inner| select(inner))
        };
        f.debug_struct("DomainMatcherSet")
            .field("full", &counts(|inner| inner.full.len()))
            .field("suffix", &counts(|inner| inner.suffix.len()))
            .field("keyword", &counts(|inner| inner.keywords.len()))
            .field("regex", &counts(|inner| inner.regex.len()))
            .field("matcher_count", &self.matcher_count)
            .finish()
    }
}

impl PartialEq for DomainMatcherSet {
    fn eq(&self, other: &Self) -> bool {
        self.matcher_count == other.matcher_count
            && match (&self.inner, &other.inner) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.full == b.full
                        && a.suffix == b.suffix
                        && a.keywords == b.keywords
                        && a.regex
                            .iter()
                            .map(Regex::as_str)
                            .eq(b.regex.iter().map(Regex::as_str))
                }
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl Eq for DomainMatcherSet {}

#[derive(Debug, Error)]
pub enum DomainMatcherSetError {
    #[error("keyword matchers exceed the automaton limits: {0}")]
    Keyword(#[from] aho_corasick::BuildError),
}

#[derive(Debug, Default)]
pub struct DomainMatcherSetBuilder {
    full: HashSet<Box<str>>,
    suffix: HashSet<Box<str>>,
    keywords: Vec<Box<str>>,
    regex: Vec<Regex>,
    matcher_count: usize,
}

impl DomainMatcherSetBuilder {
    /// Adds one matcher; the already compiled regex of a `regexp:` matcher is
    /// shared, not recompiled.
    pub fn insert(&mut self, matcher: &DomainMatcher, mode: DomainNameMode) {
        match matcher {
            DomainMatcher::Keyword(keyword) => self.keywords.push(lowercase_boxed(keyword)),
            DomainMatcher::Full(domain) => {
                self.full.insert(lowercase_boxed(mode.pattern(domain)));
            }
            DomainMatcher::Suffix(suffix) => {
                self.suffix.insert(lowercase_boxed(mode.pattern(suffix)));
            }
            DomainMatcher::Regex(matcher) => self.regex.push(matcher.regex().clone()),
        }
        self.matcher_count += 1;
    }

    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    pub fn build(self) -> Result<DomainMatcherSet, DomainMatcherSetError> {
        if self.matcher_count == 0 {
            return Ok(DomainMatcherSet::default());
        }
        let keyword_automaton = if self.keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .kind(Some(AhoCorasickKind::ContiguousNFA))
                    .start_kind(StartKind::Unanchored)
                    .build(self.keywords.iter().map(|keyword| keyword.as_bytes()))?,
            )
        };
        Ok(DomainMatcherSet {
            inner: Some(Box::new(DomainMatcherSetInner {
                full: self.full,
                suffix: self.suffix,
                keywords: self.keywords,
                keyword_automaton,
                regex: self.regex,
            })),
            matcher_count: self.matcher_count,
        })
    }
}

fn lowercase_boxed(value: &str) -> Box<str> {
    value.to_ascii_lowercase().into_boxed_str()
}

fn lowercase_ascii(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
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

    fn table_bytes(set: &HashSet<Box<str>>) -> usize {
        let buckets = if set.capacity() == 0 {
            0
        } else {
            (set.capacity() * 8).div_ceil(7).next_power_of_two()
        };
        buckets * (size_of::<Box<str>>() + 1)
    }

    fn heap_bytes(set: &HashSet<Box<str>>) -> usize {
        set.iter().map(|name| name.len()).sum()
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
        let inner = set.inner.as_deref().unwrap();

        let name_table_bytes = table_bytes(&inner.full) + table_bytes(&inner.suffix);
        let name_heap_bytes = heap_bytes(&inner.full) + heap_bytes(&inner.suffix);
        let keyword_list_bytes = inner.keywords.capacity() * size_of::<Box<str>>()
            + inner
                .keywords
                .iter()
                .map(|keyword| keyword.len())
                .sum::<usize>();
        let automaton_bytes = inner
            .keyword_automaton
            .as_ref()
            .map_or(0, AhoCorasick::memory_usage);
        let regex_pattern_bytes = inner
            .regex
            .iter()
            .map(|regex| regex.as_str().len())
            .sum::<usize>();
        eprintln!(
            "names: tables {name_table_bytes} B + heap {name_heap_bytes} B; keywords: list {keyword_list_bytes} B + automaton {automaton_bytes} B; regex patterns {regex_pattern_bytes} B"
        );

        let flat_vec_name_bytes = 120_000 * 32 + name_heap_bytes;
        assert!(name_table_bytes + name_heap_bytes <= flat_vec_name_bytes);
        assert!(automaton_bytes <= 1024 * 1024);

        assert!(set.matches("www.site-77777.geosite-suffix.example"));
        assert!(set.matches("host-19999.geosite-full.example"));
        assert!(!set.matches("www.host-19999.geosite-full.example"));
        assert!(set.matches("cdn.keyword-1999.test"));
        assert!(set.matches("ad42-199.tracker.example"));
        assert!(!set.matches("clean.example"));
    }
}
