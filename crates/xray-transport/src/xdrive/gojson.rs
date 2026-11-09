//! What Go's `encoding/json` does that XDRIVE's storages depend on: a
//! struct field found by its exact name or one that folds to it, and
//! `json.Marshal`'s spelling of a string.

use serde_json::{Map, Value};

/// Go's key folding for struct fields: ASCII letters in any case, the
/// Kelvin sign as `k` and the long s as `s`.
fn fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{212A}' => 'k',
            '\u{017F}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// The value Go decodes into the field `name`: the exact key, else one that
/// folds to it.
pub(crate) fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object.get(name).or_else(|| {
        let folded = fold(name);
        object
            .iter()
            .filter(|(key, _)| fold(key) == folded)
            .map(|(_, value)| value)
            .next_back()
    })
}

/// A Go `string` field: `null` or absent is empty, anything else not a
/// string fails the whole decode.
pub(crate) fn string(object: &Map<String, Value>, name: &str) -> Result<String, ()> {
    match field(object, name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(()),
    }
}

/// A Go `int64` field: a whole number in range, `null` or absent is zero.
pub(crate) fn int64(object: &Map<String, Value>, name: &str) -> Result<i64, ()> {
    match field(object, name) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(number)) => number.as_i64().ok_or(()),
        Some(_) => Err(()),
    }
}

/// A Go struct field: an object, `null` or absent being none.
pub(crate) fn object<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<Option<&'a Map<String, Value>>, ()> {
    match field(object, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(inner)) => Ok(Some(inner)),
        Some(_) => Err(()),
    }
}

/// The top-level object of a payload, as `json.Unmarshal` into a struct
/// takes it: `null` is an empty one, anything else not an object fails.
pub(crate) fn root(payload: &[u8]) -> Result<Map<String, Value>, ()> {
    match serde_json::from_str(&String::from_utf8_lossy(payload)) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(Value::Null) => Ok(Map::new()),
        _ => Err(()),
    }
}

/// `json.Marshal` of a string: quoted, with `<`, `>` and `&` escaped as
/// HTML-safe `\u00XX`, U+2028 and U+2029 escaped, and Go's short escapes.
pub(crate) fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_spelled_as_go_marshals_them() {
        assert_eq!(
            quote("a<b>&\"c\\\n\u{1}\u{2028}é"),
            r#""a\u003cb\u003e\u0026\"c\\\n\u0001\u2028é""#
        );
    }

    #[test]
    fn fields_fold_as_go_matches_them() {
        let object = root(br#"{"Access_Token":"t","expires_in":5,"x":null}"#).unwrap();
        assert_eq!(string(&object, "access_token").unwrap(), "t");
        assert_eq!(int64(&object, "expires_in").unwrap(), 5);
        assert_eq!(string(&object, "x").unwrap(), "");
        assert!(int64(&root(br#"{"n":1.5}"#).unwrap(), "n").is_err());
        assert!(root(b"[1]").is_err());
        assert!(root(b"null").unwrap().is_empty());
    }
}
