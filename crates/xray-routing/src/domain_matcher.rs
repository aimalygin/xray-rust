use std::borrow::Cow;

use regex::Regex;
use thiserror::Error;

/// One parsed `keyword:`, `full:`, `domain:` or `regexp:` rule.
///
/// [`DomainMatcher::matches`] is the linear reference implementation of the
/// matcher semantics; [`crate::DomainMatcherSet`] is the compiled form that
/// must agree with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatcher {
    Keyword(String),
    Full(String),
    Suffix(String),
    Regex(RegexMatcher),
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Keyword(keyword) => contains_ignore_ascii_case(domain, keyword),
            Self::Full(expected) => domain.eq_ignore_ascii_case(expected),
            Self::Suffix(suffix) => domain_matches_suffix(domain, suffix),
            Self::Regex(matcher) => matcher.matches(domain),
        }
    }
}

/// Selects how `full:` and `domain:` patterns are normalized when compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainNameMode {
    /// Routing targets match label-exactly: a trailing dot on either side is
    /// significant, as in [`DomainMatcher::matches`].
    Routing,
    /// DNS query names are normalized before matching, so patterns drop their
    /// trailing dots to match the same way.
    Dns,
}

impl DomainNameMode {
    pub(crate) fn pattern(self, pattern: &str) -> &str {
        match self {
            Self::Routing => pattern,
            Self::Dns => pattern.trim_end_matches('.'),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid domain regex `{pattern}`: {message}")]
pub struct DomainRegexError {
    pub pattern: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct RegexMatcher {
    regex: Regex,
}

impl RegexMatcher {
    pub fn new(pattern: impl Into<String>) -> Result<Self, DomainRegexError> {
        let pattern = pattern.into();
        let regex = Regex::new(&pattern).map_err(|error| DomainRegexError {
            pattern,
            message: error.to_string(),
        })?;
        Ok(Self { regex })
    }

    pub fn pattern(&self) -> &str {
        self.regex.as_str()
    }

    pub(crate) fn regex(&self) -> &Regex {
        &self.regex
    }

    /// Matches the ASCII-lowercased domain; the pattern itself is not
    /// lowercased and carries no case-insensitive flag.
    pub fn matches(&self, domain: &str) -> bool {
        let domain: Cow<'_, str> = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
        self.regex.is_match(&domain)
    }
}

impl PartialEq for RegexMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern() == other.pattern()
    }
}

impl Eq for RegexMatcher {}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Label-boundary suffix test shared with [`DomainMatcher::Suffix`]:
/// `suffix` matches `domain` itself or any `<label>.suffix`, ASCII
/// case-insensitively.
pub fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }

    if domain.len() <= suffix.len() {
        return false;
    }

    let boundary_index = domain.len() - suffix.len() - 1;
    let domain_bytes = domain.as_bytes();
    domain_bytes[boundary_index] == b'.'
        && domain_bytes[boundary_index + 1..].eq_ignore_ascii_case(suffix.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_full_and_suffix_match_ascii_case_insensitively() {
        assert!(DomainMatcher::Keyword("Ample".to_owned()).matches("EXAMPLE.com"));
        assert!(DomainMatcher::Keyword(String::new()).matches(""));
        assert!(!DomainMatcher::Keyword("zz".to_owned()).matches("example.com"));

        let full = DomainMatcher::Full("Example.COM".to_owned());
        assert!(full.matches("example.com"));
        assert!(!full.matches("www.example.com"));
        assert!(!full.matches("example.com."));

        let suffix = DomainMatcher::Suffix("example.com".to_owned());
        assert!(suffix.matches("EXAMPLE.com"));
        assert!(suffix.matches("a.b.example.com"));
        assert!(!suffix.matches("notexample.com"));
        assert!(!suffix.matches("example.com.evil"));
    }

    #[test]
    fn regex_matcher_lowercases_input_but_not_pattern() {
        let matcher = RegexMatcher::new(r"^api\.example\.com$").unwrap();
        assert_eq!(matcher.pattern(), r"^api\.example\.com$");
        assert!(matcher.matches("api.example.com"));
        assert!(matcher.matches("API.Example.COM"));
        assert!(!matcher.matches("api.example.org"));

        let upper = RegexMatcher::new(r"^API\.example\.com$").unwrap();
        assert!(!upper.matches("api.example.com"));
        assert!(!upper.matches("API.example.com"));

        let unicode = RegexMatcher::new("^пример\\.рф$").unwrap();
        assert!(unicode.matches("пример.рф"));

        assert_eq!(matcher, RegexMatcher::new(r"^api\.example\.com$").unwrap());
        assert_ne!(matcher, upper);
    }

    #[test]
    fn invalid_regex_reports_pattern_and_message() {
        let error = RegexMatcher::new("(").unwrap_err();
        assert_eq!(error.pattern, "(");
        assert!(!error.message.is_empty());
        assert!(error.to_string().starts_with("invalid domain regex `(`: "));
    }

    #[test]
    fn dns_mode_trims_trailing_dots_from_patterns_only() {
        assert_eq!(DomainNameMode::Dns.pattern("a.test.."), "a.test");
        assert_eq!(DomainNameMode::Routing.pattern("a.test.."), "a.test..");
        assert_eq!(DomainNameMode::Dns.pattern("..."), "");
    }
}
