//! The two S3 answers XDRIVE reads, as Go's `encoding/xml` unmarshals them
//! into Xray-core v26.10.31's `s3ListPage` and `s3ErrorCode`'s struct: a
//! strict tokenizer (well-formed tags, the five entities and character
//! references, comments, processing instructions, directives and CDATA),
//! then fields matched by local name, a repeated scalar keeping its last
//! value and a nested element inside a string field skipped.

/// `s3ListPage`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ListPage {
    pub is_truncated: bool,
    pub next_continuation_token: String,
    pub keys: Vec<String>,
    pub prefixes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Start { local: String, empty: bool },
    End { local: String },
    Text(String),
}

struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
    stack: Vec<String>,
    pending_end: Option<String>,
}

fn syntax(message: &str) -> String {
    format!("XML syntax error: {message}")
}

impl<'a> Tokenizer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            stack: Vec::new(),
            pending_end: None,
        }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.pos..]
    }

    /// The next token, `None` at the end of the input.
    fn next(&mut self) -> Result<Option<Token>, String> {
        if let Some(local) = self.pending_end.take() {
            return Ok(Some(Token::End { local }));
        }
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                if self.stack.is_empty() {
                    return Ok(None);
                }
                return Err(syntax("unexpected EOF"));
            }
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                let text = decode_text(&rest[..end])?;
                self.pos += end;
                return Ok(Some(Token::Text(text)));
            }
            if let Some(body) = rest.strip_prefix("<?") {
                let end = body.find("?>").ok_or_else(|| syntax("unexpected EOF"))?;
                self.pos += 2 + end + 2;
                continue;
            }
            if let Some(body) = rest.strip_prefix("<!--") {
                let end = body.find("-->").ok_or_else(|| syntax("unexpected EOF"))?;
                if body[..end].contains("--") {
                    return Err(syntax("invalid sequence \"--\" not allowed in comments"));
                }
                self.pos += 4 + end + 3;
                continue;
            }
            if let Some(body) = rest.strip_prefix("<![CDATA[") {
                let end = body
                    .find("]]>")
                    .ok_or_else(|| syntax("unexpected EOF in CDATA section"))?;
                let text = body[..end].replace("\r\n", "\n").replace('\r', "\n");
                check_chars(&text)?;
                self.pos += 9 + end + 3;
                return Ok(Some(Token::Text(text)));
            }
            if rest.starts_with("<!") {
                self.pos += directive_len(rest)?;
                continue;
            }
            if let Some(body) = rest.strip_prefix("</") {
                let end = body.find('>').ok_or_else(|| syntax("unexpected EOF"))?;
                let name = body[..end].trim_end_matches([' ', '\t', '\r', '\n']);
                check_name(name)?;
                let local = local_name(name);
                match self.stack.pop() {
                    Some(open) if open == name => {}
                    Some(open) => {
                        return Err(syntax(&format!("element <{open}> closed by </{name}>")))
                    }
                    None => return Err(syntax(&format!("unexpected end element </{name}>"))),
                }
                self.pos += 2 + end + 1;
                return Ok(Some(Token::End { local }));
            }
            let body = &rest[1..];
            let (name, after) =
                take_name(body).ok_or_else(|| syntax("expected element name after <"))?;
            let mut cursor = &body[after..];
            loop {
                cursor = cursor.trim_start_matches([' ', '\t', '\r', '\n']);
                if let Some(after) = cursor.strip_prefix("/>") {
                    self.pos = self.input.len() - after.len();
                    self.pending_end = Some(local_name(name));
                    return Ok(Some(Token::Start {
                        local: local_name(name),
                        empty: true,
                    }));
                }
                if let Some(after) = cursor.strip_prefix('>') {
                    self.pos = self.input.len() - after.len();
                    self.stack.push(name.to_owned());
                    return Ok(Some(Token::Start {
                        local: local_name(name),
                        empty: false,
                    }));
                }
                let (_, after) = take_name(cursor)
                    .ok_or_else(|| syntax("expected attribute name in element"))?;
                cursor = cursor[after..].trim_start_matches([' ', '\t', '\r', '\n']);
                cursor = cursor
                    .strip_prefix('=')
                    .ok_or_else(|| syntax("attribute name without = in element"))?
                    .trim_start_matches([' ', '\t', '\r', '\n']);
                let quote = cursor
                    .chars()
                    .next()
                    .filter(|c| *c == '"' || *c == '\'')
                    .ok_or_else(|| syntax("unquoted or missing attribute value in element"))?;
                let value = &cursor[1..];
                let end = value.find(quote).ok_or_else(|| syntax("unexpected EOF"))?;
                if value[..end].contains('<') {
                    return Err(syntax("unescaped < inside quoted string"));
                }
                decode_text(&value[..end])?;
                cursor = &value[end + 1..];
            }
        }
    }
}

/// How long a `<!...>` directive is, its quotes and nested `<...>` included.
fn directive_len(rest: &str) -> Result<usize, String> {
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    let mut quote = None;
    for (index, &byte) in bytes.iter().enumerate() {
        match quote {
            Some(q) if byte == q => quote = None,
            Some(_) => {}
            None => match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(index + 1);
                    }
                }
                _ => {}
            },
        }
    }
    Err(syntax("unexpected EOF"))
}

/// Go's `isName` start and rest, over the bytes a name may hold.
fn take_name(input: &str) -> Option<(&str, usize)> {
    let mut end = 0;
    for (index, ch) in input.char_indices() {
        let ok = if index == 0 {
            ch.is_alphabetic() || ch == '_' || ch == ':'
        } else {
            ch.is_alphanumeric() || matches!(ch, '_' | ':' | '.' | '-') || is_combining(ch)
        };
        if !ok {
            break;
        }
        end = index + ch.len_utf8();
    }
    (end > 0).then(|| (&input[..end], end))
}

fn is_combining(ch: char) -> bool {
    matches!(ch, '\u{00B7}' | '\u{0300}'..='\u{036F}' | '\u{203F}'..='\u{2040}')
}

fn check_name(name: &str) -> Result<(), String> {
    match take_name(name) {
        Some((_, end)) if end == name.len() => Ok(()),
        _ => Err(syntax(&format!("invalid XML name: {name}"))),
    }
}

/// The local part of a name: after its first colon, unless that colon
/// starts or ends it.
fn local_name(name: &str) -> String {
    match name.find(':') {
        Some(index) if index >= 1 && index < name.len() - 1 => name[index + 1..].to_owned(),
        _ => name.to_owned(),
    }
}

/// Character data with its entities replaced and line ends normalized.
fn decode_text(raw: &str) -> Result<String, String> {
    let raw = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw.as_str();
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let end = after
            .find(';')
            .ok_or_else(|| syntax("invalid character entity &"))?;
        let entity = &after[..end];
        let ch = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "apos" => '\'',
            "quot" => '"',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = entity.strip_prefix('#') {
                    dec.parse::<u32>().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32)
                    .filter(|ch| in_character_range(*ch))
                    .ok_or_else(|| syntax(&format!("invalid character entity &{entity};")))?
            }
        };
        out.push(ch);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    check_chars(&out)?;
    Ok(out)
}

fn in_character_range(ch: char) -> bool {
    matches!(ch, '\u{09}' | '\u{0A}' | '\u{0D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn check_chars(text: &str) -> Result<(), String> {
    match text.chars().find(|ch| !in_character_range(*ch)) {
        Some(ch) => Err(syntax(&format!(
            "illegal character code U+{:04X}",
            ch as u32
        ))),
        None => Ok(()),
    }
}

/// The root element: the first start element, whatever comes before it.
fn root(tokens: &mut Tokenizer<'_>) -> Result<String, String> {
    loop {
        match tokens.next()? {
            Some(Token::Start { local, .. }) => return Ok(local),
            Some(_) => continue,
            None => return Err("EOF".to_owned()),
        }
    }
}

/// The text of the element just opened, skipping the elements inside it.
fn text_of(tokens: &mut Tokenizer<'_>) -> Result<String, String> {
    let mut text = String::new();
    let mut depth = 0usize;
    loop {
        match tokens.next()? {
            Some(Token::Text(chunk)) if depth == 0 => text.push_str(&chunk),
            Some(Token::Text(_)) => {}
            Some(Token::Start { .. }) => depth += 1,
            Some(Token::End { .. }) if depth == 0 => return Ok(text),
            Some(Token::End { .. }) => depth -= 1,
            None => return Err(syntax("unexpected EOF")),
        }
    }
}

fn skip(tokens: &mut Tokenizer<'_>) -> Result<(), String> {
    text_of(tokens).map(|_| ())
}

/// Go's `strconv.ParseBool` of the trimmed text; empty text is false.
fn parse_bool(text: &str) -> Result<bool, String> {
    match text.trim_matches([' ', '\t', '\r', '\n']) {
        "" => Ok(false),
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        other => Err(format!(
            "strconv.ParseBool: parsing {other:?}: invalid syntax"
        )),
    }
}

/// One field struct of a slice: its one string field `field`.
fn one_field(tokens: &mut Tokenizer<'_>, field: &str) -> Result<String, String> {
    let mut value = String::new();
    loop {
        match tokens.next()? {
            Some(Token::Start { local, .. }) if local == field => value = text_of(tokens)?,
            Some(Token::Start { .. }) => skip(tokens)?,
            Some(Token::Text(_)) => {}
            Some(Token::End { .. }) => return Ok(value),
            None => return Err(syntax("unexpected EOF")),
        }
    }
}

/// `xml.Unmarshal(payload, &s3ListPage{})`.
pub(crate) fn parse_list_page(payload: &[u8]) -> Result<ListPage, String> {
    let text = std::str::from_utf8(payload).map_err(|_| syntax("invalid UTF-8"))?;
    let mut tokens = Tokenizer::new(text);
    let name = root(&mut tokens)?;
    if name != "ListBucketResult" {
        return Err(format!(
            "expected element type <ListBucketResult> but have <{name}>"
        ));
    }
    let mut page = ListPage::default();
    loop {
        match tokens.next()? {
            Some(Token::Start { local, .. }) => match local.as_str() {
                "IsTruncated" => page.is_truncated = parse_bool(&text_of(&mut tokens)?)?,
                "NextContinuationToken" => page.next_continuation_token = text_of(&mut tokens)?,
                "Contents" => page.keys.push(one_field(&mut tokens, "Key")?),
                "CommonPrefixes" => page.prefixes.push(one_field(&mut tokens, "Prefix")?),
                _ => skip(&mut tokens)?,
            },
            Some(Token::Text(_)) => {}
            Some(Token::End { .. }) => return Ok(page),
            None => return Err(syntax("unexpected EOF")),
        }
    }
}

/// `s3ErrorCode`: the `Code` of an `Error` document, empty for anything
/// else.
pub(crate) fn error_code(payload: &[u8]) -> String {
    let parse = || -> Result<String, String> {
        let text = std::str::from_utf8(payload).map_err(|_| syntax("invalid UTF-8"))?;
        let mut tokens = Tokenizer::new(text);
        if root(&mut tokens)? != "Error" {
            return Err("not an Error".to_owned());
        }
        one_field(&mut tokens, "Code")
    };
    parse().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_reads_its_keys_prefixes_and_token() {
        let page = parse_list_page(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name>
<IsTruncated>true</IsTruncated><NextContinuationToken>tok&amp;en</NextContinuationToken>
<Contents><Key>root/a.seg</Key><Size>3</Size></Contents>
<Contents><Key><![CDATA[root/<b>]]></Key></Contents>
<CommonPrefixes><Prefix>root/dir/</Prefix></CommonPrefixes></ListBucketResult>"#,
        )
        .unwrap();
        assert_eq!(
            page,
            ListPage {
                is_truncated: true,
                next_continuation_token: "tok&en".to_owned(),
                keys: vec!["root/a.seg".to_owned(), "root/<b>".to_owned()],
                prefixes: vec!["root/dir/".to_owned()],
            }
        );
    }

    #[test]
    fn go_rules_for_odd_documents() {
        // A namespace prefix is not part of the name; a nested element in a
        // string field is skipped; the last of a repeated scalar wins.
        let page = parse_list_page(
            b"<s3:ListBucketResult xmlns:s3='x'><s3:Contents><s3:Key>a<i>skip</i>b</s3:Key></s3:Contents>\
<IsTruncated>1</IsTruncated><IsTruncated>false</IsTruncated></s3:ListBucketResult>",
        )
        .unwrap();
        assert_eq!(page.keys, ["ab"]);
        assert!(!page.is_truncated);
        assert!(parse_list_page(
            b"<ListBucketResult><IsTruncated>yes</IsTruncated></ListBucketResult>"
        )
        .is_err());
        assert!(parse_list_page(b"<Other/>").is_err());
        assert!(parse_list_page(b"<ListBucketResult><Contents>").is_err());
        assert!(parse_list_page(b"<ListBucketResult>&bogus;</ListBucketResult>").is_err());
        assert!(parse_list_page(b"<ListBucketResult></Other>").is_err());
        assert_eq!(
            parse_list_page(b"<ListBucketResult/>").unwrap(),
            ListPage::default()
        );
        assert_eq!(
            error_code(b"<Error><Code>NoSuchKey</Code><Message>m</Message></Error>"),
            "NoSuchKey"
        );
        assert_eq!(error_code(b"<NotError><Code>X</Code></NotError>"), "");
        assert_eq!(error_code(b"plain text"), "");
    }
}
