//! A template's `namesRegex` as Go's `regexp` reads it: its RE2 syntax with
//! Perl's extensions translated for the `regex` crate, and
//! `FindAllStringSubmatch`'s walk over the matches.
//!
//! The two engines agree on leftmost-first matching, but not on syntax:
//! Go's `\d`, `\s`, `\w` and `\b` are ASCII, Go reads `[`, `&&`, `--` and
//! `~~` inside a class as plain characters and `{` that starts no repeat as
//! itself, takes octal escapes and `\Q...\E`, and refuses flags but `imsU`,
//! capture names of more than word characters, repeats above 1000 and a
//! repeat of a repeat. The translation writes every character of a class as
//! an escape, so the `regex` crate's class syntax never sees one.

use regex::Regex;

/// Go's `maxRepeat`.
const MAX_REPEAT: u32 = 1000;

/// A compiled `namesRegex`.
#[derive(Clone, Debug)]
pub(crate) struct GoRegex {
    regex: Regex,
}

impl GoRegex {
    /// `regexp.Compile`.
    pub(crate) fn compile(pattern: &str) -> Result<Self, String> {
        let translated = translate(pattern)?;
        let regex =
            Regex::new(&translated).map_err(|error| format!("error parsing regexp: {error}"))?;
        Ok(Self { regex })
    }

    /// `NumSubexp`.
    pub(crate) fn num_subexp(&self) -> usize {
        self.regex.captures_len() - 1
    }

    /// `FindAllStringSubmatch(text, -1)`: every match, an empty one right
    /// after the previous match left out, its groups empty when unmatched.
    pub(crate) fn find_all_submatch(&self, text: &str) -> Vec<Vec<String>> {
        let mut found = Vec::new();
        let mut pos = 0;
        let mut prev_end: Option<usize> = None;
        while pos <= text.len() {
            let Some(captures) = self.regex.captures_at(text, pos) else {
                break;
            };
            let whole = captures.get(0).expect("a match");
            let mut accept = true;
            if whole.end() == pos {
                if Some(whole.start()) == prev_end {
                    accept = false;
                }
                pos += text[pos..].chars().next().map_or(1, char::len_utf8);
            } else {
                pos = whole.end();
            }
            prev_end = Some(whole.end());
            if accept {
                found.push(
                    (0..captures.len())
                        .map(|group| {
                            captures
                                .get(group)
                                .map_or_else(String::new, |m| m.as_str().to_owned())
                        })
                        .collect(),
                );
            }
        }
        found
    }
}

fn error(code: &str, expr: &str) -> String {
    format!("error parsing regexp: {code}: `{expr}`")
}

struct Translator<'a> {
    pattern: &'a str,
    chars: Vec<(usize, char)>,
    pos: usize,
    out: String,
    /// Open groups.
    depth: usize,
    /// Whether the last item was a repeat, for Go's nested-repeat check.
    /// Where the repeat operator just before the cursor began, if any.
    last_repeat: Option<usize>,
    /// Whether something stands before a repeat operator.
    has_operand: bool,
}

/// The `regex` crate pattern that matches what Go's `pattern` matches.
pub(crate) fn translate(pattern: &str) -> Result<String, String> {
    let mut translator = Translator {
        pattern,
        chars: pattern.char_indices().collect(),
        pos: 0,
        out: String::new(),
        depth: 0,
        last_repeat: None,
        has_operand: false,
    };
    translator.run()?;
    Ok(translator.out)
}

impl Translator<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).map(|(_, c)| *c)
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).map(|(_, c)| *c)
    }

    fn rest(&self) -> &str {
        match self.chars.get(self.pos) {
            Some((at, _)) => &self.pattern[*at..],
            None => "",
        }
    }

    fn operand(&mut self, text: &str) {
        self.out.push_str(text);
        self.has_operand = true;
        self.last_repeat = None;
    }

    fn run(&mut self) -> Result<(), String> {
        while let Some(c) = self.peek() {
            match c {
                '(' => self.group()?,
                ')' => {
                    if self.depth == 0 {
                        return Err(error("unexpected )", self.pattern));
                    }
                    self.depth -= 1;
                    self.pos += 1;
                    self.operand(")");
                }
                '|' => {
                    self.pos += 1;
                    self.out.push('|');
                    self.has_operand = false;
                    self.last_repeat = None;
                }
                '*' | '+' | '?' => {
                    let start = self.pos;
                    self.pos += 1;
                    self.repeat(&c.to_string(), start)?;
                }
                '{' => match self.counted()? {
                    Some(text) => {
                        let start = self.pos - text.chars().count();
                        self.repeat(&text, start)?;
                    }
                    // Perl: a brace that starts no repeat is itself.
                    None => {
                        self.pos += 1;
                        self.operand("\\{");
                    }
                },
                '[' => {
                    let class = self.class()?;
                    self.operand(&class);
                }
                '\\' => self.escape()?,
                '.' | '^' | '$' => {
                    self.pos += 1;
                    self.operand(&c.to_string());
                }
                other => {
                    self.pos += 1;
                    self.operand(&regex::escape(&other.to_string()));
                }
            }
        }
        if self.depth > 0 {
            return Err(error("missing closing )", self.pattern));
        }
        Ok(())
    }

    /// A repeat operator that began at `start`, with its lazy `?`, checked
    /// in Go's order: a repeat right after another first, then one with
    /// nothing to repeat, each error naming what Go's does.
    fn repeat(&mut self, op: &str, start: usize) -> Result<(), String> {
        let lazy = self.peek() == Some('?');
        if lazy {
            self.pos += 1;
        }
        if let Some(previous) = self.last_repeat {
            return Err(error(
                "invalid nested repetition operator",
                &self.slice(previous, self.pos),
            ));
        }
        if !self.has_operand {
            return Err(error(
                "missing argument to repetition operator",
                &self.slice(start, self.pos),
            ));
        }
        self.out.push_str(op);
        if lazy {
            self.out.push('?');
        }
        self.last_repeat = Some(start);
        Ok(())
    }

    /// `{n}`, `{n,}` or `{n,m}` at the cursor, `None` when the brace starts
    /// none of them.
    fn counted(&mut self) -> Result<Option<String>, String> {
        let rest = self.rest();
        let Some(close) = rest.find('}') else {
            return Ok(None);
        };
        let inner = &rest[1..close];
        let (min, max) = match inner.split_once(',') {
            Some((min, max)) => (min, Some(max)),
            None => (inner, None),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(min) || max.is_some_and(|m| !m.is_empty() && !digits(m)) {
            return Ok(None);
        }
        let parse = |s: &str| s.parse::<u32>().unwrap_or(u32::MAX);
        let low = parse(min);
        let high = max.filter(|m| !m.is_empty()).map(parse);
        if low > MAX_REPEAT || high.is_some_and(|h| h > MAX_REPEAT || h < low) {
            return Err(error("invalid repeat count", &rest[..=close]));
        }
        let text = rest[..=close].to_owned();
        self.pos += text.chars().count();
        Ok(Some(text))
    }

    fn group(&mut self) -> Result<(), String> {
        let rest = self.rest().to_owned();
        // Go takes a named capture only when something follows its opening.
        let named = if rest.len() > 4 && rest.starts_with("(?P<") {
            rest.strip_prefix("(?P<")
        } else if rest.len() > 3 && rest.starts_with("(?<") {
            rest.strip_prefix("(?<")
        } else {
            None
        };
        if let Some(after) = named {
            let Some(end) = after.find('>') else {
                return Err(error("invalid named capture", &rest));
            };
            let name = &after[..end];
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(error(
                    "invalid named capture",
                    &rest[..rest.len() - after.len() + end + 1],
                ));
            }
            let consumed = rest.len() - after.len() + end + 1;
            self.pos += rest[..consumed].chars().count();
            self.out.push_str(&format!("(?P<{name}>"));
            self.depth += 1;
            self.has_operand = false;
            self.last_repeat = None;
            return Ok(());
        }
        if let Some(after) = rest.strip_prefix("(?") {
            // Flags: (?flags) or (?flags:re), flags from imsU with one '-'.
            let mut seen_minus = false;
            let mut seen_flag = false;
            let mut flags = String::new();
            for (index, c) in after.char_indices() {
                match c {
                    'i' | 'm' | 's' | 'U' => {
                        seen_flag = true;
                        flags.push(c);
                    }
                    '-' if !seen_minus => {
                        seen_minus = true;
                        seen_flag = false;
                        flags.push('-');
                    }
                    ':' | ')' => {
                        if seen_minus && !seen_flag {
                            return Err(error(
                                "invalid or unsupported Perl syntax",
                                &rest[..2 + index + 1],
                            ));
                        }
                        self.pos += rest[..2 + index + 1].chars().count();
                        if c == ':' {
                            self.out.push_str(&format!("(?{flags}:"));
                            self.depth += 1;
                            self.has_operand = false;
                        } else if !flags.is_empty() {
                            self.out.push_str(&format!("(?{flags})"));
                        }
                        // An empty `(?)` sets no flag, in Go as here.
                        self.last_repeat = None;
                        return Ok(());
                    }
                    _ => {
                        return Err(error(
                            "invalid or unsupported Perl syntax",
                            &rest[..2 + index + c.len_utf8()],
                        ))
                    }
                }
            }
            return Err(error("invalid or unsupported Perl syntax", &rest));
        }
        self.pos += 1;
        self.out.push('(');
        self.depth += 1;
        self.has_operand = false;
        self.last_repeat = None;
        Ok(())
    }

    /// An escape outside a class.
    fn escape(&mut self) -> Result<(), String> {
        let Some(c) = self.peek_at(1) else {
            return Err(error("trailing backslash at end of expression", ""));
        };
        match c {
            'd' | 'D' | 's' | 'S' | 'w' | 'W' => {
                self.pos += 2;
                let class = perl_class(c);
                self.operand(&format!("[{class}]"));
            }
            'b' | 'B' => {
                self.pos += 2;
                self.operand(&format!("(?-u:\\{c})"));
            }
            'A' | 'z' => {
                self.pos += 2;
                self.operand(&format!("\\{c}"));
            }
            'p' | 'P' => {
                let class = self.unicode_class()?;
                self.operand(&class);
            }
            'Q' => {
                self.pos += 2;
                let rest = self.rest().to_owned();
                let (literal, consumed) = match rest.find("\\E") {
                    Some(end) => (&rest[..end], end + 2),
                    None => (rest.as_str(), rest.len()),
                };
                self.pos += rest[..consumed].chars().count();
                if !literal.is_empty() {
                    let escaped = regex::escape(literal);
                    self.operand(&format!("(?:{escaped})"));
                }
            }
            _ => {
                let ch = self.escaped_char()?;
                self.operand(&format!("\\x{{{:X}}}", ch as u32));
            }
        }
        Ok(())
    }

    /// `parseEscape` of a character: octal, hex, the control letters and
    /// punctuation.
    fn escaped_char(&mut self) -> Result<char, String> {
        let start = self.pos;
        self.pos += 1;
        let c = self
            .peek()
            .ok_or_else(|| error("trailing backslash at end of expression", ""))?;
        self.pos += 1;
        let invalid = |t: &Self| error("invalid escape sequence", &t.slice(start, t.pos));
        let ch = match c {
            '1'..='7' if !self.peek().is_some_and(|d| ('0'..='7').contains(&d)) => {
                return Err(invalid(self));
            }
            '0'..='7' => {
                let mut value = c as u32 - '0' as u32;
                for _ in 1..3 {
                    match self.peek() {
                        Some(d @ '0'..='7') => {
                            value = value * 8 + (d as u32 - '0' as u32);
                            self.pos += 1;
                        }
                        _ => break,
                    }
                }
                char::from_u32(value).ok_or_else(|| invalid(self))?
            }
            'x' => {
                if self.peek() == Some('{') {
                    self.pos += 1;
                    let mut value: u32 = 0;
                    let mut digits = 0;
                    loop {
                        match self.peek() {
                            Some('}') if digits > 0 => {
                                self.pos += 1;
                                break;
                            }
                            Some(d) if d.is_ascii_hexdigit() => {
                                value = value.saturating_mul(16) + d.to_digit(16).unwrap();
                                if value > 0x10FFFF {
                                    return Err(invalid(self));
                                }
                                digits += 1;
                                self.pos += 1;
                            }
                            _ => return Err(invalid(self)),
                        }
                    }
                    char::from_u32(value).ok_or_else(|| invalid(self))?
                } else {
                    let (Some(hi), Some(lo)) = (self.peek(), self.peek_at(1)) else {
                        return Err(invalid(self));
                    };
                    let (Some(hi), Some(lo)) = (hi.to_digit(16), lo.to_digit(16)) else {
                        return Err(invalid(self));
                    };
                    self.pos += 2;
                    char::from_u32(hi * 16 + lo).ok_or_else(|| invalid(self))?
                }
            }
            'a' => '\u{07}',
            'f' => '\u{0C}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{0B}',
            c if c.is_ascii() && !c.is_ascii_alphanumeric() => c,
            _ => return Err(invalid(self)),
        };
        Ok(ch)
    }

    fn slice(&self, from: usize, to: usize) -> String {
        let start = self
            .chars
            .get(from)
            .map_or(self.pattern.len(), |(at, _)| *at);
        let end = self.chars.get(to).map_or(self.pattern.len(), |(at, _)| *at);
        self.pattern[start..end].to_owned()
    }

    /// `\pN`, `\p{Name}`, `\PN`, `\P{Name}` or `\p{^Name}`.
    fn unicode_class(&mut self) -> Result<String, String> {
        let start = self.pos;
        let negated = self.peek_at(1) == Some('P');
        self.pos += 2;
        let name = match self.peek() {
            Some('{') => {
                let rest = self.rest().to_owned();
                let end = rest.find('}').ok_or_else(|| {
                    error(
                        "invalid character class range",
                        &self.slice(start, self.chars.len()),
                    )
                })?;
                self.pos += rest[..=end].chars().count();
                rest[1..end].to_owned()
            }
            Some(c) => {
                self.pos += 1;
                c.to_string()
            }
            None => {
                return Err(error(
                    "invalid character class range",
                    &self.slice(start, self.pos),
                ))
            }
        };
        let (name, negated) = match name.strip_prefix('^') {
            Some(name) => (name.to_owned(), !negated),
            None => (name, negated),
        };
        if name != "Any" && GO_UNICODE_NAMES.binary_search(&name.as_str()).is_err() {
            return Err(error(
                "invalid character class range",
                &self.slice(start, self.pos),
            ));
        }
        Ok(format!("\\{}{{{name}}}", if negated { 'P' } else { 'p' }))
    }

    /// A class, every character written as an escape.
    fn class(&mut self) -> Result<String, String> {
        let start = self.pos;
        self.pos += 1;
        let mut out = String::from("[");
        if self.peek() == Some('^') {
            self.pos += 1;
            out.push('^');
        }
        let mut first = true;
        let mut items = 0;
        loop {
            let Some(c) = self.peek() else {
                return Err(error(
                    "missing closing ]",
                    &self.slice(start, self.chars.len()),
                ));
            };
            if c == ']' && !first {
                self.pos += 1;
                break;
            }
            first = false;
            // POSIX classes.
            if c == '[' && self.peek_at(1) == Some(':') {
                let rest = self.rest().to_owned();
                if let Some(end) = rest[2..].find(":]") {
                    let name = &rest[2..2 + end];
                    let bare = name.strip_prefix('^').unwrap_or(name);
                    if !POSIX_CLASSES.contains(&bare) {
                        return Err(error("invalid character class range", &rest[..end + 4]));
                    }
                    self.pos += rest[..end + 4].chars().count();
                    out.push_str(&format!("[:{name}:]"));
                    items += 1;
                    continue;
                }
            }
            if c == '\\' {
                match self.peek_at(1) {
                    Some(p @ ('d' | 'D' | 's' | 'S' | 'w' | 'W')) => {
                        self.pos += 2;
                        out.push_str(&format!("[{}]", perl_class(p)));
                        items += 1;
                        continue;
                    }
                    Some('p' | 'P') => {
                        let class = self.unicode_class()?;
                        out.push_str(&class);
                        items += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            let range_start = self.pos;
            let low = self.class_char()?;
            let mut high = low;
            if self.peek() == Some('-') && self.peek_at(1).is_some_and(|n| n != ']') {
                self.pos += 1;
                high = self.class_char()?;
                if high < low {
                    // Go names the range alone.
                    return Err(error(
                        "invalid character class range",
                        &self.slice(range_start, self.pos),
                    ));
                }
            }
            if low == high {
                out.push_str(&format!("\\x{{{:X}}}", low as u32));
            } else {
                out.push_str(&format!("\\x{{{:X}}}-\\x{{{:X}}}", low as u32, high as u32));
            }
            items += 1;
        }
        if items == 0 {
            return Err(error("missing closing ]", &self.slice(start, self.pos)));
        }
        out.push(']');
        Ok(out)
    }

    fn class_char(&mut self) -> Result<char, String> {
        match self.peek() {
            Some('\\') => self.escaped_char(),
            Some(c) => {
                self.pos += 1;
                Ok(c)
            }
            None => Err(error("missing closing ]", self.pattern)),
        }
    }
}

/// Go's ASCII Perl classes, as class contents.
fn perl_class(c: char) -> &'static str {
    match c {
        'd' => "0-9",
        'D' => "^0-9",
        's' => "\\t\\n\\f\\r ",
        'S' => "^\\t\\n\\f\\r ",
        'w' => "0-9A-Za-z_",
        _ => "^0-9A-Za-z_",
    }
}

/// The names `\p` takes in Go 1.27: `unicode.Categories` and
/// `unicode.Scripts` of its Unicode 17.0.0 tables, besides `Any`, sorted.
const GO_UNICODE_NAMES: [&str; 212] = [
    "Adlam",
    "Ahom",
    "Anatolian_Hieroglyphs",
    "Arabic",
    "Armenian",
    "Avestan",
    "Balinese",
    "Bamum",
    "Bassa_Vah",
    "Batak",
    "Bengali",
    "Beria_Erfe",
    "Bhaiksuki",
    "Bopomofo",
    "Brahmi",
    "Braille",
    "Buginese",
    "Buhid",
    "C",
    "Canadian_Aboriginal",
    "Carian",
    "Caucasian_Albanian",
    "Cc",
    "Cf",
    "Chakma",
    "Cham",
    "Cherokee",
    "Chorasmian",
    "Cn",
    "Co",
    "Common",
    "Coptic",
    "Cs",
    "Cuneiform",
    "Cypriot",
    "Cypro_Minoan",
    "Cyrillic",
    "Deseret",
    "Devanagari",
    "Dives_Akuru",
    "Dogra",
    "Duployan",
    "Egyptian_Hieroglyphs",
    "Elbasan",
    "Elymaic",
    "Ethiopic",
    "Garay",
    "Georgian",
    "Glagolitic",
    "Gothic",
    "Grantha",
    "Greek",
    "Gujarati",
    "Gunjala_Gondi",
    "Gurmukhi",
    "Gurung_Khema",
    "Han",
    "Hangul",
    "Hanifi_Rohingya",
    "Hanunoo",
    "Hatran",
    "Hebrew",
    "Hiragana",
    "Imperial_Aramaic",
    "Inherited",
    "Inscriptional_Pahlavi",
    "Inscriptional_Parthian",
    "Javanese",
    "Kaithi",
    "Kannada",
    "Katakana",
    "Kawi",
    "Kayah_Li",
    "Kharoshthi",
    "Khitan_Small_Script",
    "Khmer",
    "Khojki",
    "Khudawadi",
    "Kirat_Rai",
    "L",
    "LC",
    "Lao",
    "Latin",
    "Lepcha",
    "Limbu",
    "Linear_A",
    "Linear_B",
    "Lisu",
    "Ll",
    "Lm",
    "Lo",
    "Lt",
    "Lu",
    "Lycian",
    "Lydian",
    "M",
    "Mahajani",
    "Makasar",
    "Malayalam",
    "Mandaic",
    "Manichaean",
    "Marchen",
    "Masaram_Gondi",
    "Mc",
    "Me",
    "Medefaidrin",
    "Meetei_Mayek",
    "Mende_Kikakui",
    "Meroitic_Cursive",
    "Meroitic_Hieroglyphs",
    "Miao",
    "Mn",
    "Modi",
    "Mongolian",
    "Mro",
    "Multani",
    "Myanmar",
    "N",
    "Nabataean",
    "Nag_Mundari",
    "Nandinagari",
    "Nd",
    "New_Tai_Lue",
    "Newa",
    "Nko",
    "Nl",
    "No",
    "Nushu",
    "Nyiakeng_Puachue_Hmong",
    "Ogham",
    "Ol_Chiki",
    "Ol_Onal",
    "Old_Hungarian",
    "Old_Italic",
    "Old_North_Arabian",
    "Old_Permic",
    "Old_Persian",
    "Old_Sogdian",
    "Old_South_Arabian",
    "Old_Turkic",
    "Old_Uyghur",
    "Oriya",
    "Osage",
    "Osmanya",
    "P",
    "Pahawh_Hmong",
    "Palmyrene",
    "Pau_Cin_Hau",
    "Pc",
    "Pd",
    "Pe",
    "Pf",
    "Phags_Pa",
    "Phoenician",
    "Pi",
    "Po",
    "Ps",
    "Psalter_Pahlavi",
    "Rejang",
    "Runic",
    "S",
    "Samaritan",
    "Saurashtra",
    "Sc",
    "Sharada",
    "Shavian",
    "Siddham",
    "Sidetic",
    "SignWriting",
    "Sinhala",
    "Sk",
    "Sm",
    "So",
    "Sogdian",
    "Sora_Sompeng",
    "Soyombo",
    "Sundanese",
    "Sunuwar",
    "Syloti_Nagri",
    "Syriac",
    "Tagalog",
    "Tagbanwa",
    "Tai_Le",
    "Tai_Tham",
    "Tai_Viet",
    "Tai_Yo",
    "Takri",
    "Tamil",
    "Tangsa",
    "Tangut",
    "Telugu",
    "Thaana",
    "Thai",
    "Tibetan",
    "Tifinagh",
    "Tirhuta",
    "Todhri",
    "Tolong_Siki",
    "Toto",
    "Tulu_Tigalari",
    "Ugaritic",
    "Vai",
    "Vithkuqi",
    "Wancho",
    "Warang_Citi",
    "Yezidi",
    "Yi",
    "Z",
    "Zanabazar_Square",
    "Zl",
    "Zp",
    "Zs",
];

/// Go's POSIX class names.
const POSIX_CLASSES: [&str; 14] = [
    "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower", "print", "punct",
    "space", "upper", "word", "xdigit",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn names(pattern: &str, text: &str) -> Vec<Vec<String>> {
        GoRegex::compile(pattern).unwrap().find_all_submatch(text)
    }

    #[test]
    fn listings_parse_as_in_go() {
        let found = names(
            "<d:href>/folder/([^<]+)</d:href>",
            "<d:href>/folder/a~b</d:href>\n<d:href>/folder/c</d:href>",
        );
        assert_eq!(
            found,
            [
                vec!["<d:href>/folder/a~b</d:href>", "a~b"],
                vec!["<d:href>/folder/c</d:href>", "c"]
            ]
        );
        assert_eq!(
            names(r#""name":"([^"]+)""#, r#"{"name":"x","name":"y"}"#).len(),
            2
        );
    }

    #[test]
    fn perl_classes_are_ascii() {
        assert!(names(r"(\d+)", "٣").is_empty());
        assert_eq!(names(r"(\w+)", "é_a1"), [vec!["_a1", "_a1"]]);
        assert_eq!(names(r"(\s)", "\u{0B}\u{85} ").len(), 1);
        assert_eq!(names(r"[\d]", "a1").len(), 1);
        assert_eq!(names(r"[\D]", "1a").len(), 1);
    }

    #[test]
    fn class_syntax_is_go_s() {
        assert_eq!(names("[[]", "[").len(), 1);
        assert_eq!(names("[a&&b]", "&").len(), 1);
        assert_eq!(names("[]a]", "]").len(), 1);
        assert_eq!(names("[a-]", "-").len(), 1);
        assert_eq!(names("[[:digit:]x]", "x5").len(), 2);
        assert!(GoRegex::compile("[z-a]").is_err());
        assert!(GoRegex::compile("[a").is_err());
        assert!(GoRegex::compile("[]").is_err());
    }

    #[test]
    fn escapes_and_braces_are_go_s() {
        assert_eq!(names(r"\101", "A").len(), 1);
        assert_eq!(names(r"\x41\x{42}", "AB").len(), 1);
        assert_eq!(names(r"\Qa.b\E", "a.b axb").len(), 1);
        assert_eq!(names("a{", "a{").len(), 1);
        assert_eq!(names("a{,2}", "a{,2}").len(), 1);
        assert_eq!(names("a{2}", "aa").len(), 1);
        assert!(GoRegex::compile(r"\1").is_err());
        assert!(GoRegex::compile(r"\e").is_err());
        assert!(GoRegex::compile("a{1001}").is_err());
        assert!(GoRegex::compile("a{3,2}").is_err());
    }

    #[test]
    fn groups_and_flags_are_go_s() {
        assert_eq!(
            GoRegex::compile("(a)(?:b)(?P<n>c)(?<m>d)")
                .unwrap()
                .num_subexp(),
            3
        );
        assert_eq!(names("(?i)ABC", "abc").len(), 1);
        assert_eq!(names("(?s:a.b)", "a\nb").len(), 1);
        assert!(GoRegex::compile("(?x)a").is_err());
        assert!(GoRegex::compile("(?P<a.b>x)").is_err());
        assert!(GoRegex::compile("(?=a)").is_err());
        assert!(GoRegex::compile("(?-)a").is_err());
        assert!(GoRegex::compile("a**").is_err());
        assert!(GoRegex::compile("a{2}*").is_err());
        assert!(GoRegex::compile("*a").is_err());
        assert!(GoRegex::compile("a)").is_err());
        assert!(GoRegex::compile("(a").is_err());
        assert!(GoRegex::compile("a*?").is_ok());
    }

    #[test]
    fn empty_matches_follow_go() {
        // Go: "", "", "" at 0, 1 and 2 for a* on "bb"... and none right
        // after a match.
        assert_eq!(names("a*", "baaab").len(), 3);
        assert_eq!(names("a*", "").len(), 1);
        assert_eq!(names("(a)|b", "ab")[1], vec!["b", ""]);
    }
}
