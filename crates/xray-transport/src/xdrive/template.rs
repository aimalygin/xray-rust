//! The `template` service, as Xray-core v26.10.31's `template.go` reaches an
//! HTTP storage: put, get, delete and list requests a JSON template
//! describes, with `{name}`, `{folder}`, `{secretN}`, `{data}`, `{prefix}` and
//! `{token}` replaced; no auth, static headers, OAuth 2 with a refreshed
//! token, or Basic; a two-step request through a URL the first answer gives
//! at `hrefPath`; and listings read with Go's `regexp`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use http::Method;
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::client::ServiceResponse;
use super::goregex::GoRegex;
use super::http_storage::{token_expiry, HttpShared, SessionHttp};
use super::jsonpath::{json_number, json_string};
use super::redirect::{new_request_url, Followed};
use super::s3::{jitter, INITIAL_BACKOFF, MAX_ATTEMPTS, MAX_BACKOFF};
use super::storage::{Entry, Storage, StorageError};

/// Xray-core's `flatSeparator`.
pub(crate) const FLAT_SEPARATOR: &str = "~";
/// Xray-core's `driveMaxInflight`, the default concurrency.
const DEFAULT_CONCURRENCY: usize = super::drive::MAX_INFLIGHT;
/// Xray-core's `maxTemplateConcurrency`.
const MAX_CONCURRENCY: usize = 256;
/// A template answer is read whole by Xray-core; here at most this much.
const MAX_ANSWER: usize = 64 << 20;
/// A token answer is read up to 1 MiB.
const MAX_TOKEN_ANSWER: usize = 1 << 20;

/// `authTemplate`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthTemplate {
    pub kind: String,
    pub header: Vec<(String, String)>,
    pub username: String,
    pub password: String,
    pub token_url: String,
    pub form: Vec<(String, String)>,
    pub token_path: String,
    pub expiry_path: String,
}

/// `opTemplate`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpTemplate {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub names_regex: String,
    pub href_path: String,
    pub href_method: String,
}

/// `storageTemplate`, decoded and checked as `newTemplateStorage` checks it.
#[derive(Clone, Debug)]
pub(crate) struct StorageTemplate {
    pub flatten: bool,
    pub concurrency: usize,
    pub auth: AuthTemplate,
    pub put: OpTemplate,
    pub get: OpTemplate,
    pub delete: OpTemplate,
    pub list: OpTemplate,
    pub retry_status: Vec<i64>,
    pub rate_reason: String,
    names: GoRegex,
}

/// Go's `encoding/json` key folding for struct fields: ASCII letters in any
/// case, the Kelvin sign as `k` and the long s as `s`.
fn fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{212A}' => 'k',
            '\u{017F}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// A field of the object Go would decode into: the exact name, else one
/// that folds to it.
fn field<'a>(object: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a Value> {
    object.get(name).or_else(|| {
        let folded = fold(name);
        object
            .iter()
            .filter(|(key, _)| fold(key) == folded)
            .map(|(_, value)| value)
            .next_back()
    })
}

fn type_error(path: &str, want: &str) -> String {
    format!("json: cannot unmarshal into Go struct field {path} of type {want}")
}

fn decode_string(value: Option<&Value>, path: &str) -> Result<String, String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(type_error(path, "string")),
    }
}

fn decode_bool(value: Option<&Value>, path: &str) -> Result<bool, String> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(type_error(path, "bool")),
    }
}

fn decode_int(value: &Value, path: &str) -> Result<i64, String> {
    match value {
        Value::Null => Ok(0),
        Value::Number(number) => number.as_i64().ok_or_else(|| type_error(path, "int")),
        _ => Err(type_error(path, "int")),
    }
}

/// A Go `map[string]string`: null reads as none, a null value as empty.
fn decode_map(value: Option<&Value>, path: &str) -> Result<Vec<(String, String)>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(object)) => object
            .iter()
            .map(|(key, value)| match value {
                Value::String(text) => Ok((key.clone(), text.clone())),
                Value::Null => Ok((key.clone(), String::new())),
                _ => Err(type_error(path, "string")),
            })
            .collect(),
        Some(_) => Err(type_error(path, "map[string]string")),
    }
}

fn decode_object<'a>(
    value: Option<&'a Value>,
    path: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(type_error(path, "object")),
    }
}

fn decode_op(value: Option<&Value>, path: &str) -> Result<OpTemplate, String> {
    let Some(object) = decode_object(value, path)? else {
        return Ok(OpTemplate::default());
    };
    Ok(OpTemplate {
        method: decode_string(field(object, "method"), path)?,
        url: decode_string(field(object, "url"), path)?,
        headers: decode_map(field(object, "headers"), path)?,
        body: decode_string(field(object, "body"), path)?,
        names_regex: decode_string(field(object, "namesRegex"), path)?,
        href_path: decode_string(field(object, "hrefPath"), path)?,
        href_method: decode_string(field(object, "hrefMethod"), path)?,
    })
}

impl StorageTemplate {
    /// `newTemplateStorage`'s reading of `template`: Go's JSON decoding,
    /// then the four operations, the list's regexp with one group, and the
    /// concurrency between 1 and 256.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let root: Value =
            serde_json::from_str(text).map_err(|error| format!("invalid template > {error}"))?;
        let invalid = |error: String| format!("invalid template > {error}");
        let empty = serde_json::Map::new();
        let object = match &root {
            Value::Null => &empty,
            Value::Object(object) => object,
            _ => return Err(invalid(type_error("storageTemplate", "object"))),
        };
        let auth = match decode_object(field(object, "auth"), "auth").map_err(invalid)? {
            None => AuthTemplate::default(),
            Some(auth) => AuthTemplate {
                kind: decode_string(field(auth, "type"), "auth.type").map_err(invalid)?,
                header: decode_map(field(auth, "header"), "auth.header").map_err(invalid)?,
                username: decode_string(field(auth, "username"), "auth.username")
                    .map_err(invalid)?,
                password: decode_string(field(auth, "password"), "auth.password")
                    .map_err(invalid)?,
                token_url: decode_string(field(auth, "tokenUrl"), "auth.tokenUrl")
                    .map_err(invalid)?,
                form: decode_map(field(auth, "form"), "auth.form").map_err(invalid)?,
                token_path: decode_string(field(auth, "tokenPath"), "auth.tokenPath")
                    .map_err(invalid)?,
                expiry_path: decode_string(field(auth, "expiryPath"), "auth.expiryPath")
                    .map_err(invalid)?,
            },
        };
        let (retry_status, rate_reason) =
            match decode_object(field(object, "retry"), "retry").map_err(invalid)? {
                None => (Vec::new(), String::new()),
                Some(retry) => {
                    let status = match field(retry, "status") {
                        None | Some(Value::Null) => Vec::new(),
                        Some(Value::Array(items)) => items
                            .iter()
                            .map(|item| decode_int(item, "retry.status"))
                            .collect::<Result<_, _>>()
                            .map_err(invalid)?,
                        Some(_) => return Err(invalid(type_error("retry.status", "[]int"))),
                    };
                    (
                        status,
                        decode_string(field(retry, "rateReason"), "retry.rateReason")
                            .map_err(invalid)?,
                    )
                }
            };
        let concurrency = match field(object, "concurrency") {
            None => 0,
            Some(value) => decode_int(value, "concurrency").map_err(invalid)?,
        };
        let put = decode_op(field(object, "put"), "put").map_err(invalid)?;
        let get = decode_op(field(object, "get"), "get").map_err(invalid)?;
        let delete = decode_op(field(object, "delete"), "delete").map_err(invalid)?;
        let list = decode_op(field(object, "list"), "list").map_err(invalid)?;
        let flatten = decode_bool(field(object, "flatten"), "flatten").map_err(invalid)?;
        if put.url.is_empty() || get.url.is_empty() || list.url.is_empty() || delete.url.is_empty()
        {
            return Err("template needs put, get, list and delete operations".to_owned());
        }
        if list.names_regex.is_empty() {
            return Err("template list needs a namesRegex".to_owned());
        }
        let names = GoRegex::compile(&list.names_regex)
            .map_err(|error| format!("bad namesRegex > {error}"))?;
        if names.num_subexp() < 1 {
            return Err("namesRegex needs one capture group".to_owned());
        }
        let concurrency = if concurrency <= 0 {
            DEFAULT_CONCURRENCY
        } else {
            (concurrency as u64).min(MAX_CONCURRENCY as u64) as usize
        };
        Ok(Self {
            flatten,
            concurrency,
            auth,
            put,
            get,
            delete,
            list,
            retry_status,
            rate_reason,
            names,
        })
    }
}

/// `flatten`: a name with its separators made flat.
pub(crate) fn flatten(name: &str) -> String {
    name.replace('/', FLAT_SEPARATOR)
}

/// `subst`: every `{key}` replaced by its value. Xray-core replaces in Go's
/// random map order; here in the order of the keys.
pub(crate) fn subst(template: &str, vars: &[(String, Zeroizing<String>)]) -> String {
    if template.is_empty() || !template.contains('{') {
        return template.to_owned();
    }
    let mut out = template.to_owned();
    for (key, value) in vars {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

/// What every session of one template storage shares.
pub(crate) struct TemplateShared {
    pub template: StorageTemplate,
    folder: String,
    secrets: Vec<Zeroizing<String>>,
    pub http: Arc<HttpShared>,
    token: Mutex<Option<(Zeroizing<String>, Instant)>>,
    token_lock: tokio::sync::Mutex<()>,
    pub backoff: Duration,
}

impl std::fmt::Debug for TemplateShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateShared")
            .field("folder", &self.folder)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

impl TemplateShared {
    pub(crate) fn new(
        template: StorageTemplate,
        folder: String,
        secrets: Vec<Zeroizing<String>>,
        http: Arc<HttpShared>,
    ) -> Self {
        Self {
            template,
            folder,
            secrets,
            http,
            token: Mutex::new(None),
            token_lock: tokio::sync::Mutex::new(()),
            backoff: INITIAL_BACKOFF,
        }
    }

    /// `baseVars`: `{folder}` and `{secretN}`.
    fn base_vars(&self) -> Vec<(String, Zeroizing<String>)> {
        let mut vars = vec![("folder".to_owned(), Zeroizing::new(self.folder.clone()))];
        for (index, secret) in self.secrets.iter().enumerate() {
            vars.push((format!("secret{index}"), secret.clone()));
        }
        vars
    }

    fn stored_name(&self, name: &str) -> String {
        if self.template.flatten {
            flatten(name)
        } else {
            name.to_owned()
        }
    }

    /// `retryable`: a status the template lists, or a 403 whose answer
    /// names a reason at `rateReason`.
    fn retryable(&self, status: u16, payload: &[u8]) -> bool {
        self.template
            .retry_status
            .iter()
            .any(|code| *code == i64::from(status))
            || (status == 403
                && !self.template.rate_reason.is_empty()
                && !json_string(payload, &self.template.rate_reason).is_empty())
    }

    /// `accessToken`: the cached token, or a new one from `tokenUrl`.
    async fn access_token(&self) -> Result<Zeroizing<String>, String> {
        let _guard = self.token_lock.lock().await;
        if let Some((token, expiry)) = self.token.lock().unwrap().as_ref() {
            if !token.is_empty() && Instant::now() < *expiry {
                return Ok(token.clone());
            }
        }
        let vars = self.base_vars();
        // Xray-core writes the form unescaped, in Go's random map order;
        // here in the template's order.
        let body: Vec<String> = self
            .template
            .auth
            .form
            .iter()
            .map(|(key, value)| format!("{key}={}", subst(value, &vars).as_str()))
            .collect();
        let url = new_request_url(&self.template.auth.token_url)
            .map_err(|error| format!("failed to build the token request > {error}"))?;
        let request = Followed {
            method: Method::POST,
            url,
            headers: vec![(
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: Bytes::from(body.join("&")),
            max_body: MAX_TOKEN_ANSWER,
        };
        let answer = self
            .http
            .send_token(request)
            .await
            .map_err(|error| format!("failed to fetch the token > {error}"))?;
        let payload = &answer.body[..answer.body.len().min(MAX_TOKEN_ANSWER)];
        if answer.status != 200 {
            return Err(format!(
                "the token endpoint answered {}: {}",
                answer.status,
                String::from_utf8_lossy(payload)
            ));
        }
        let path = if self.template.auth.token_path.is_empty() {
            "access_token"
        } else {
            &self.template.auth.token_path
        };
        let token = json_string(payload, path);
        if token.is_empty() {
            return Err(format!("the token response has no token at {path}"));
        }
        let mut lifetime = 3600;
        if !self.template.auth.expiry_path.is_empty() {
            let n = json_number(payload, &self.template.auth.expiry_path);
            if n > 0 {
                lifetime = n;
            }
        }
        if lifetime > 60 {
            lifetime -= 60;
        }
        let token = Zeroizing::new(token);
        *self.token.lock().unwrap() = Some((token.clone(), token_expiry(Instant::now(), lifetime)));
        Ok(token)
    }

    fn invalidate_token(&self) {
        *self.token.lock().unwrap() = None;
    }

    /// `authHeaders`.
    async fn auth_headers(
        &self,
        vars: &mut Vec<(String, Zeroizing<String>)>,
    ) -> Result<Vec<(String, String)>, String> {
        match self.template.auth.kind.as_str() {
            "" | "none" => Ok(Vec::new()),
            kind @ ("static" | "oauth2") => {
                if kind == "oauth2" {
                    let token = self.access_token().await?;
                    vars.retain(|(key, _)| key != "token");
                    vars.push(("token".to_owned(), token));
                }
                Ok(self
                    .template
                    .auth
                    .header
                    .iter()
                    .map(|(key, value)| (key.clone(), subst(value, vars)))
                    .collect())
            }
            "basic" => {
                let user = subst(&self.template.auth.username, vars);
                let pass = subst(&self.template.auth.password, vars);
                let pair = Zeroizing::new(format!("{user}:{pass}"));
                Ok(vec![(
                    "Authorization".to_owned(),
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
                    ),
                )])
            }
            other => Err(format!("unsupported auth type: {other}")),
        }
    }
}

/// One session's view of a template storage.
#[derive(Debug)]
pub(crate) struct TemplateStorage {
    shared: Arc<TemplateShared>,
    http: SessionHttp,
    inflight: Semaphore,
}

/// An operation to send: the template's, or the presigned one an `href`
/// gives, which takes neither auth nor headers.
struct Op<'a> {
    method: &'a str,
    url: String,
    headers: &'a [(String, String)],
    presigned: bool,
}

impl TemplateStorage {
    pub(crate) fn new(shared: Arc<TemplateShared>, http: SessionHttp) -> Self {
        let concurrency = shared.template.concurrency;
        Self {
            shared,
            http,
            inflight: Semaphore::new(concurrency),
        }
    }

    /// `do`: up to eight tries, a growing jittered pause between them.
    async fn exchange(
        &self,
        op: &Op<'_>,
        vars: &[(String, Zeroizing<String>)],
        body: Option<Bytes>,
    ) -> Result<ServiceResponse, StorageError> {
        let mut backoff = self.shared.backoff;
        let mut last = None;
        let url_text = if op.presigned {
            op.url.clone()
        } else {
            subst(&op.url, vars)
        };
        let method = if op.method.is_empty() {
            "GET"
        } else {
            op.method
        };
        // `http.NewRequest` refuses a bad method or URL before any try; a
        // scheme or host the transport cannot reach fails each try instead.
        let built =
            |error: String| StorageError::Failed(format!("failed to build request > {error}"));
        let method =
            Method::from_bytes(method.as_bytes()).map_err(|error| built(error.to_string()))?;
        let url = new_request_url(&url_text).map_err(built)?;
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(jitter(backoff)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            let mut vars = vars.to_vec();
            let auth = if op.presigned {
                Vec::new()
            } else {
                match self.shared.auth_headers(&mut vars).await {
                    Ok(headers) => headers,
                    Err(error) => {
                        last = Some(error);
                        continue;
                    }
                }
            };
            let mut headers = auth;
            for (key, value) in op.headers {
                headers.push((key.clone(), subst(value, &vars)));
            }
            let request = Followed {
                method: method.clone(),
                url: url.clone(),
                headers,
                body: body.clone().unwrap_or_default(),
                max_body: MAX_ANSWER,
            };
            let permit = self
                .inflight
                .acquire()
                .await
                .map_err(|_| StorageError::Failed("the session is closed".to_owned()))?;
            let answer = self.http.send_following(request).await;
            drop(permit);
            let answer = match answer {
                Ok(answer) => answer,
                Err(error) => {
                    last = Some(format!("request failed > {error}"));
                    continue;
                }
            };
            if answer.status == 401 && self.shared.template.auth.kind == "oauth2" && !op.presigned {
                self.shared.invalidate_token();
                last = Some("the service rejected the token".to_owned());
                continue;
            }
            if self.shared.retryable(answer.status, &answer.body) {
                last = Some(format!("the service answered {}", answer.status));
                continue;
            }
            return Ok(answer);
        }
        Err(StorageError::Failed(last.unwrap_or_default()))
    }

    /// `run`: the operation, through the URL its answer gives at `hrefPath`
    /// when it has one.
    async fn run(
        &self,
        op: &super::template::OpTemplate,
        vars: &[(String, Zeroizing<String>)],
        body: Option<Bytes>,
    ) -> Result<ServiceResponse, StorageError> {
        let first = Op {
            method: &op.method,
            url: op.url.clone(),
            headers: &op.headers,
            presigned: false,
        };
        if op.href_path.is_empty() {
            return self.exchange(&first, vars, body).await;
        }
        let answer = self.exchange(&first, vars, None).await?;
        if !(200..300).contains(&answer.status) {
            return Ok(answer);
        }
        let href = json_string(&answer.body, &op.href_path);
        if href.is_empty() {
            return Err(StorageError::Failed(format!(
                "the response has no href at {}",
                op.href_path
            )));
        }
        let second = Op {
            method: &op.href_method,
            url: href,
            headers: &[],
            presigned: true,
        };
        self.exchange(&second, vars, body).await
    }

    fn vars_with(&self, key: &str, value: String) -> Vec<(String, Zeroizing<String>)> {
        let mut vars = self.shared.base_vars();
        vars.push((key.to_owned(), Zeroizing::new(value)));
        vars
    }
}

fn answered(what: &str, name: &str, answer: &ServiceResponse) -> StorageError {
    StorageError::Failed(format!(
        "{what} of {name} answered {}: {}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    ))
}

#[async_trait]
impl Storage for TemplateStorage {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError> {
        let mut vars = self.vars_with("name", self.shared.stored_name(name));
        let template = &self.shared.template;
        let body = if template.put.body.is_empty() {
            data
        } else {
            vars.push((
                "data".to_owned(),
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&data)),
            ));
            Bytes::from(subst(&template.put.body, &vars))
        };
        let answer = self.run(&template.put, &vars, Some(body)).await?;
        if !(200..300).contains(&answer.status) {
            return Err(answered("put", name, &answer));
        }
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let vars = self.vars_with("name", self.shared.stored_name(name));
        let answer = self.run(&self.shared.template.get, &vars, None).await?;
        match answer.status {
            200..=299 => Ok(answer.body),
            404 => Err(StorageError::NotFound),
            _ => Err(answered("get", name, &answer)),
        }
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let vars = self.vars_with("name", self.shared.stored_name(name));
        let answer = self.run(&self.shared.template.delete, &vars, None).await?;
        if answer.status == 404 || (200..300).contains(&answer.status) {
            return Ok(());
        }
        Err(answered("delete", name, &answer))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Entry>, StorageError> {
        let flat = self.shared.stored_name(prefix);
        let vars = self.vars_with("prefix", flat.clone());
        let template = &self.shared.template;
        let answer = self.run(&template.list, &vars, None).await?;
        if answer.status == 404 {
            return Ok(Vec::new());
        }
        if !(200..300).contains(&answer.status) {
            return Err(answered("list", prefix, &answer));
        }
        let text = String::from_utf8_lossy(&answer.body);
        let matches = template.names.find_all_submatch(&text);
        if !template.flatten {
            return Ok(matches
                .into_iter()
                .map(|groups| Entry::named(groups.into_iter().nth(1).unwrap_or_default()))
                .collect());
        }
        let want = format!("{flat}{FLAT_SEPARATOR}");
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        for groups in matches {
            let name = groups.get(1).map(String::as_str).unwrap_or_default();
            let Some(rest) = name.strip_prefix(want.as_str()) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let rest = rest.split(FLAT_SEPARATOR).next().unwrap_or_default();
            if seen.insert(rest.to_owned()) {
                entries.push(Entry::named(rest));
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAV: &str = r#"{"flatten": true,
        "auth": {"type": "basic", "username": "{secret0}", "password": "{secret1}"},
        "put": {"method": "PUT", "url": "https://dav.example/{folder}/{name}"},
        "get": {"method": "GET", "url": "https://dav.example/{folder}/{name}"},
        "delete": {"method": "DELETE", "url": "https://dav.example/{folder}/{name}"},
        "list": {"method": "PROPFIND", "url": "https://dav.example/{folder}/",
            "namesRegex": "<d:href>/folder/([^<]+)</d:href>"}}"#;

    #[test]
    fn templates_decode_as_go_decodes_them() {
        let template = StorageTemplate::parse(DAV).unwrap();
        assert!(template.flatten);
        assert_eq!(template.concurrency, 64);
        assert_eq!(template.auth.kind, "basic");
        assert_eq!(template.list.method, "PROPFIND");
        // Field names fold case, as Go's do.
        let upper = DAV
            .replace("\"put\"", "\"PUT\"")
            .replace("\"url\"", "\"URL\"");
        assert!(StorageTemplate::parse(&upper).is_ok());
        let missing = DAV.replace("\"delete\"", "\"remove\"");
        assert_eq!(
            StorageTemplate::parse(&missing).unwrap_err(),
            "template needs put, get, list and delete operations"
        );
        assert!(StorageTemplate::parse("null").is_err());
        assert!(StorageTemplate::parse("\"text\"")
            .unwrap_err()
            .starts_with("invalid template"));
        assert!(StorageTemplate::parse(&DAV.replace("true", "1")).is_err());
        let one = DAV.replace("([^<]+)", "[^<]+");
        assert_eq!(
            StorageTemplate::parse(&one).unwrap_err(),
            "namesRegex needs one capture group"
        );
        let bad = DAV.replace("([^<]+)", "([^<]+");
        assert!(StorageTemplate::parse(&bad)
            .unwrap_err()
            .starts_with("bad namesRegex"));
        let busy = DAV.replacen(
            "{\"flatten\": true,",
            "{\"flatten\": true, \"concurrency\": 1000,",
            1,
        );
        assert_eq!(StorageTemplate::parse(&busy).unwrap().concurrency, 256);
        let float = DAV.replacen(
            "{\"flatten\": true,",
            "{\"flatten\": true, \"concurrency\": 1.5,",
            1,
        );
        assert!(StorageTemplate::parse(&float).is_err());
    }

    #[test]
    fn substitution_and_flattening() {
        let vars = vec![
            ("folder".to_owned(), Zeroizing::new("root".to_owned())),
            ("name".to_owned(), Zeroizing::new("a~b".to_owned())),
        ];
        assert_eq!(
            subst("https://h/{folder}/{name}?{x}", &vars),
            "https://h/root/a~b?{x}"
        );
        assert_eq!(subst("no braces", &vars), "no braces");
        assert_eq!(
            flatten("streams/s/c2s/000000001.seg"),
            "streams~s~c2s~000000001.seg"
        );
    }
}
