//! Xray-core v26.10.31's `jsonpath.go`: a value found by walking a JSON
//! answer through object keys split at dots.

use serde_json::Value;

/// `jsonWalk`: the value at `path`, `None` when the payload is not JSON or
/// a step is missing or not an object. Go reads a byte that is not UTF-8 in
/// a string as U+FFFD; outside one it is a syntax error either way.
fn walk(payload: &[u8], path: &str) -> Option<Value> {
    let mut node: Value = serde_json::from_str(&String::from_utf8_lossy(payload)).ok()?;
    for key in path.split('.') {
        node = match node {
            Value::Object(mut object) => object.remove(key)?,
            _ => return None,
        };
    }
    Some(node)
}

/// `jsonString`: the string at `path`, empty for anything else.
pub(crate) fn json_string(payload: &[u8], path: &str) -> String {
    match walk(payload, path) {
        Some(Value::String(text)) => text,
        _ => String::new(),
    }
}

/// `jsonNumber`: the number at `path` cut to an integer as Go's
/// `int64(float64)` cuts it, zero for anything else.
pub(crate) fn json_number(payload: &[u8], path: &str) -> i64 {
    match walk(payload, path) {
        Some(Value::Number(number)) => number.as_f64().map(go_int64).unwrap_or(0),
        _ => 0,
    }
}

/// Go's conversion of a finite float to `int64`: toward zero, and beyond
/// the range whatever the machine gives, which the Go spec leaves to the
/// implementation. arm64, where phones and Apple's computers run Xray-core,
/// saturates, and so does this; amd64 gives the minimum on either side.
fn go_int64(value: f64) -> i64 {
    if value >= 9_223_372_036_854_775_807.0 {
        i64::MAX
    } else if value <= -9_223_372_036_854_775_808.0 {
        i64::MIN
    } else {
        value as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_walk_objects_only() {
        let payload =
            br#"{"access_token":"tok","a":{"b":{"c":"deep"}},"n":3599.9,"arr":[1],"s":"7"}"#;
        assert_eq!(json_string(payload, "access_token"), "tok");
        assert_eq!(json_string(payload, "a.b.c"), "deep");
        assert_eq!(json_string(payload, "a.b"), "");
        assert_eq!(json_string(payload, "arr.0"), "");
        assert_eq!(json_string(payload, "missing"), "");
        assert_eq!(json_string(b"not json", "x"), "");
        assert_eq!(json_number(payload, "n"), 3599);
        assert_eq!(json_number(payload, "s"), 0);
        assert_eq!(json_number(br#"{"n":-2.7}"#, "n"), -2);
        // Beyond int64, arm64's answer; the oracle vectors stay inside it,
        // where Go's is the same everywhere.
        assert_eq!(json_number(br#"{"n":1e300}"#, "n"), i64::MAX);
        assert_eq!(json_number(br#"{"n":-1e300}"#, "n"), i64::MIN);
        assert_eq!(json_number(br#"{"n":9223372036854775807}"#, "n"), i64::MAX);
        assert_eq!(
            json_number(br#"{"n":1e18}"#, "n"),
            1_000_000_000_000_000_000
        );
        // The last of a repeated key wins, as in Go.
        assert_eq!(json_string(br#"{"k":"a","k":"b"}"#, "k"), "b");
        assert_eq!(json_string(b"{\"k\":\"a\xffb\"}", "k"), "a\u{fffd}b");
    }
}
