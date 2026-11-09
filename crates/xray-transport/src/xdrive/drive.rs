//! The `google-drive` service, as Xray-core v26.10.31's `drive.go` reaches
//! Google Drive's v3 API: an access token from the refresh token, objects
//! as files in the folder `remoteFolder` names by id, their names flat with
//! `~`, small ones in the description and larger ones uploaded as media,
//! and file ids remembered by name for every session of the outbound. The
//! same files serve as slots, written and read again by id.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use http::Method;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use xray_proxy::go_url::{self, Encoding};
use zeroize::Zeroizing;

use super::client::ServiceResponse;
use super::gojson;
use super::http_storage::{token_expiry, HttpShared, SessionHttp};
use super::redirect::{new_request_url, Followed};
use super::s3::{jitter, INITIAL_BACKOFF, MAX_ATTEMPTS, MAX_BACKOFF};
use super::slots::SlotStore;
use super::storage::{Entry, Storage, StorageError};
use super::template::flatten;

pub(crate) const DRIVE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) const DRIVE_FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
pub(crate) const DRIVE_UPLOAD_URL: &str =
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name";
const FLAT_SEPARATOR: &str = "~";
const BOUNDARY: &str = "xdrive-boundary";
const PAGE_SIZE: usize = 1000;
/// `driveMaxInflight`: requests in flight a session, and HTTP/1.1
/// connections a host.
pub(crate) const MAX_INFLIGHT: usize = 32;
/// The largest object that goes in a description instead of a body.
const INLINE_LIMIT: usize = 12000;
/// Xray-core reads an answer whole; here at most this much.
const MAX_ANSWER: usize = 64 << 20;
const MAX_TOKEN_ANSWER: usize = 1 << 20;
const JSON: &str = "application/json; charset=UTF-8";

/// Where a storage's requests go, Google's own unless a test says otherwise.
#[derive(Clone, Debug)]
pub(crate) struct DriveUrls {
    pub token: String,
    pub files: String,
    pub upload: String,
}

impl Default for DriveUrls {
    fn default() -> Self {
        Self {
            token: DRIVE_TOKEN_URL.to_owned(),
            files: DRIVE_FILES_URL.to_owned(),
            upload: DRIVE_UPLOAD_URL.to_owned(),
        }
    }
}

/// What the sessions of one storage share: the folder, the secrets, the
/// connections, the token and the ids found so far.
pub(crate) struct DriveShared {
    folder: String,
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    pub http: Arc<HttpShared>,
    pub urls: DriveUrls,
    pub backoff: Duration,
    token: Mutex<Option<(Zeroizing<String>, Instant)>>,
    token_lock: tokio::sync::Mutex<()>,
    ids: Mutex<HashMap<String, String>>,
}

impl std::fmt::Debug for DriveShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriveShared")
            .field("folder", &self.folder)
            .finish_non_exhaustive()
    }
}

impl DriveShared {
    /// `newDriveStorage`: a folder and three secrets, none empty.
    pub(crate) fn new(
        folder: &str,
        secrets: &[Zeroizing<String>],
        http: Arc<HttpShared>,
    ) -> Result<Self, String> {
        if folder.is_empty() {
            return Err(r#"empty "remoteFolder", it must be a Google Drive folder id"#.to_owned());
        }
        if secrets.len() != 3 {
            return Err(
                "Google Drive needs 3 secrets in order of ClientID, ClientSecret, RefreshToken"
                    .to_owned(),
            );
        }
        if let Some(index) = secrets.iter().position(|secret| secret.is_empty()) {
            return Err(format!("Google Drive secret {index} is empty"));
        }
        Ok(Self {
            folder: folder.to_owned(),
            client_id: secrets[0].clone(),
            client_secret: secrets[1].clone(),
            refresh_token: secrets[2].clone(),
            http,
            urls: DriveUrls::default(),
            backoff: INITIAL_BACKOFF,
            token: Mutex::new(None),
            token_lock: tokio::sync::Mutex::new(()),
            ids: Mutex::new(HashMap::new()),
        })
    }

    fn remember(&self, name: &str, id: &str) {
        self.ids
            .lock()
            .unwrap()
            .insert(name.to_owned(), id.to_owned());
    }

    fn forget(&self, name: &str) {
        self.ids.lock().unwrap().remove(name);
    }

    fn cached(&self, name: &str) -> Option<String> {
        self.ids.lock().unwrap().get(name).cloned()
    }

    fn invalidate_token(&self) {
        *self.token.lock().unwrap() = None;
    }

    /// `accessToken`: the cached token, or one the refresh token gets.
    async fn access_token(&self) -> Result<Zeroizing<String>, String> {
        let _guard = self.token_lock.lock().await;
        if let Some((token, expiry)) = self.token.lock().unwrap().as_ref() {
            if !token.is_empty() && Instant::now() < *expiry {
                return Ok(token.clone());
            }
        }
        let form = Zeroizing::new(go_url::encode_values(&[
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("refresh_token", self.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ]));
        let url = new_request_url(&self.urls.token)
            .map_err(|error| format!("failed to build the token request > {error}"))?;
        let answer = self
            .http
            .send_token(Followed {
                method: Method::POST,
                url,
                headers: vec![(
                    "Content-Type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                )],
                body: Bytes::copy_from_slice(form.as_bytes()),
                max_body: MAX_TOKEN_ANSWER,
            })
            .await
            .map_err(|error| format!("failed to refresh the access token > {error}"))?;
        let body = &answer.body[..answer.body.len().min(MAX_TOKEN_ANSWER)];
        if answer.status != 200 {
            return Err(format!(
                "the token endpoint answered {}: {}",
                answer.status,
                String::from_utf8_lossy(body)
            ));
        }
        let parsed = gojson::root(body).and_then(|object| {
            Ok((
                gojson::string(&object, "access_token")?,
                gojson::int64(&object, "expires_in")?,
            ))
        });
        let Ok((token, mut lifetime)) = parsed else {
            return Err("failed to parse the token response".to_owned());
        };
        if token.is_empty() {
            return Err("the token endpoint returned no access token".to_owned());
        }
        if lifetime > 60 {
            lifetime -= 60;
        }
        let token = Zeroizing::new(token);
        let expiry = token_expiry(Instant::now(), lifetime);
        *self.token.lock().unwrap() = Some((token.clone(), expiry));
        Ok(token)
    }
}

/// `rateLimited`: whether a 403's JSON names one of Drive's rate limits.
pub(crate) fn rate_limited(payload: &[u8]) -> bool {
    let parsed = gojson::root(payload).and_then(|root| {
        let Some(error) = gojson::object(&root, "error")? else {
            return Ok((String::new(), Vec::new()));
        };
        let status = gojson::string(error, "status")?;
        let reasons = match gojson::field(error, "errors") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    serde_json::Value::Object(item) => gojson::string(item, "reason"),
                    serde_json::Value::Null => Ok(String::new()),
                    _ => Err(()),
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(()),
        };
        Ok((status, reasons))
    });
    let Ok((status, reasons)) = parsed else {
        return false;
    };
    reasons.iter().any(|reason| {
        matches!(
            reason.as_str(),
            "rateLimitExceeded" | "userRateLimitExceeded" | "sharingRateLimitExceeded"
        )
    }) || status == "RESOURCE_EXHAUSTED"
}

/// `retryableStatus`.
fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// `quoteDriveValue`: a value inside the single quotes of a Drive query.
pub(crate) fn quote_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// `multipartBody`: an upload's metadata and data.
pub(crate) fn multipart_body(metadata: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(metadata.len() + data.len() + 160);
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(metadata);
    body.extend_from_slice(
        format!("\r\n--{BOUNDARY}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// The metadata `json.Marshal` gives a map: keys sorted.
fn metadata(name: Option<&str>, description: Option<&str>, parent: Option<&str>) -> String {
    let mut fields = Vec::new();
    if let Some(description) = description {
        fields.push(format!("\"description\":{}", gojson::quote(description)));
    }
    if let Some(name) = name {
        fields.push(format!("\"name\":{}", gojson::quote(name)));
    }
    if let Some(parent) = parent {
        fields.push(format!("\"parents\":[{}]", gojson::quote(parent)));
    }
    format!("{{{}}}", fields.join(","))
}

/// One session's view of the folder: its connections and its requests in
/// flight, with the token and ids of the storage.
#[derive(Debug)]
pub(crate) struct DriveStorage {
    shared: Arc<DriveShared>,
    http: SessionHttp,
    inflight: Semaphore,
}

/// A file a listing found.
struct DriveFile {
    id: String,
    description: String,
}

impl DriveStorage {
    pub(crate) fn new(shared: Arc<DriveShared>, http: SessionHttp) -> Self {
        Self {
            shared,
            http,
            inflight: Semaphore::new(MAX_INFLIGHT),
        }
    }

    fn file_url(&self, id: &str, query: &str) -> String {
        format!(
            "{}/{}?{query}",
            self.shared.urls.files,
            go_url::escape(id.as_bytes(), Encoding::PathSegment)
        )
    }

    /// `do`: up to eight tries with a growing jittered pause, after a failed
    /// request, a rejected token, a 403 for a rate limit or a status worth
    /// another try.
    async fn exchange(
        &self,
        method: Method,
        target: &str,
        content_type: &str,
        body: Option<Bytes>,
    ) -> Result<ServiceResponse, StorageError> {
        let url = new_request_url(target).map_err(|error| {
            StorageError::Failed(format!("failed to build a Drive request > {error}"))
        })?;
        let mut backoff = self.shared.backoff;
        let mut last = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(jitter(backoff)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            let token = match self.shared.access_token().await {
                Ok(token) => token,
                Err(error) => {
                    last = error;
                    continue;
                }
            };
            let mut headers = vec![(
                "Authorization".to_owned(),
                format!("Bearer {}", token.as_str()),
            )];
            if !content_type.is_empty() {
                headers.push(("Content-Type".to_owned(), content_type.to_owned()));
            }
            let permit = self
                .inflight
                .acquire()
                .await
                .map_err(|_| StorageError::Failed("the session is closed".to_owned()))?;
            let answer = self
                .http
                .send_following(Followed {
                    method: method.clone(),
                    url: url.clone(),
                    headers,
                    body: body.clone().unwrap_or_default(),
                    max_body: MAX_ANSWER,
                })
                .await;
            drop(permit);
            let answer = match answer {
                Ok(answer) => answer,
                Err(error) => {
                    last = format!("Drive request failed > {error}");
                    continue;
                }
            };
            if answer.status == 401 {
                self.shared.invalidate_token();
                last = "Drive rejected the access token".to_owned();
                continue;
            }
            if answer.status == 403 && rate_limited(&answer.body) {
                last = format!(
                    "Drive is rate limiting: {}",
                    String::from_utf8_lossy(&answer.body)
                );
                continue;
            }
            if retryable_status(answer.status) {
                last = format!(
                    "Drive answered {}: {}",
                    answer.status,
                    String::from_utf8_lossy(&answer.body)
                );
                continue;
            }
            return Ok(answer);
        }
        Err(StorageError::Failed(last))
    }

    /// `query`: every file of the folder that meets `condition`, by name,
    /// page after page, their ids remembered.
    async fn query(&self, condition: &str) -> Result<HashMap<String, DriveFile>, StorageError> {
        let mut found = HashMap::new();
        let mut page_token = String::new();
        let q = format!(
            "'{}' in parents and trashed = false and {condition}",
            quote_value(&self.shared.folder)
        );
        let page_size = PAGE_SIZE.to_string();
        loop {
            let mut params = vec![
                ("q", q.as_str()),
                ("fields", "nextPageToken,files(id,name,description)"),
                ("pageSize", page_size.as_str()),
                ("supportsAllDrives", "true"),
                ("includeItemsFromAllDrives", "true"),
            ];
            if !page_token.is_empty() {
                params.push(("pageToken", page_token.as_str()));
            }
            let target = format!(
                "{}?{}",
                self.shared.urls.files,
                go_url::encode_values(&params)
            );
            let answer = self.exchange(Method::GET, &target, "", None).await?;
            if answer.status != 200 {
                return Err(StorageError::Failed(format!(
                    "Drive listing answered {}: {}",
                    answer.status,
                    String::from_utf8_lossy(&answer.body)
                )));
            }
            let parsed = gojson::root(&answer.body).and_then(|root| {
                let next = gojson::string(&root, "nextPageToken")?;
                let files = match gojson::field(&root, "files") {
                    None | Some(serde_json::Value::Null) => Vec::new(),
                    Some(serde_json::Value::Array(items)) => items
                        .iter()
                        .map(|item| match item {
                            serde_json::Value::Object(file) => Ok((
                                gojson::string(file, "id")?,
                                gojson::string(file, "name")?,
                                gojson::string(file, "description")?,
                            )),
                            serde_json::Value::Null => Ok(Default::default()),
                            _ => Err(()),
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    Some(_) => return Err(()),
                };
                Ok((next, files))
            });
            let Ok((next, files)) = parsed else {
                return Err(StorageError::Failed(
                    "failed to parse the Drive listing".to_owned(),
                ));
            };
            for (id, name, description) in files {
                self.shared.remember(&name, &id);
                found.insert(name, DriveFile { id, description });
            }
            if next.is_empty() {
                return Ok(found);
            }
            page_token = next;
        }
    }

    /// `resolveID`: a name's file id, remembered or looked up.
    async fn resolve_id(&self, flat: &str) -> Result<String, StorageError> {
        if let Some(id) = self.shared.cached(flat) {
            return Ok(id);
        }
        let found = self
            .query(&format!("name = '{}'", quote_value(flat)))
            .await?;
        found
            .get(flat)
            .map(|file| file.id.clone())
            .ok_or(StorageError::NotFound)
    }

    /// `create`: a file with a description and no body; its id.
    async fn create(&self, name: &str, description: &str) -> Result<String, StorageError> {
        let flat = flatten(name);
        let body = metadata(Some(&flat), Some(description), Some(&self.shared.folder));
        let target = format!("{}?fields=id", self.shared.urls.files);
        let answer = self
            .exchange(Method::POST, &target, JSON, Some(Bytes::from(body)))
            .await?;
        if answer.status != 200 {
            return Err(StorageError::Failed(format!(
                "Drive rejected the inline upload of {name} with {}: {}",
                answer.status,
                String::from_utf8_lossy(&answer.body)
            )));
        }
        let id = parse_id(&answer.body)?;
        if !id.is_empty() {
            self.shared.remember(&flat, &id);
        }
        Ok(id)
    }

    /// `putMedia`: a file with a body, uploaded with its metadata.
    async fn put_media(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
        let flat = flatten(name);
        let body = multipart_body(
            metadata(Some(&flat), None, Some(&self.shared.folder)).as_bytes(),
            data,
        );
        let content_type = format!("multipart/related; boundary={BOUNDARY}");
        let answer = self
            .exchange(
                Method::POST,
                &self.shared.urls.upload.clone(),
                &content_type,
                Some(Bytes::from(body)),
            )
            .await?;
        if answer.status != 200 {
            return Err(StorageError::Failed(format!(
                "Drive upload of {name} answered {}: {}",
                answer.status,
                String::from_utf8_lossy(&answer.body)
            )));
        }
        let id = parse_id(&answer.body)?;
        if !id.is_empty() {
            self.shared.remember(&flat, &id);
        }
        Ok(())
    }

    /// `getInline`: the object a description holds in base64.
    async fn get_inline(&self, id: &str) -> Result<Bytes, StorageError> {
        let description = self.read_description(id).await?;
        if description.is_empty() {
            return Ok(Bytes::new());
        }
        base64::engine::general_purpose::STANDARD
            .decode(&description)
            .map(Bytes::from)
            .map_err(|error| {
                StorageError::Failed(format!("the inline data is not valid base64 > {error}"))
            })
    }

    /// `deleteID`: a file gone, a missing one too.
    async fn delete_id(&self, flat: &str, id: &str) -> Result<(), StorageError> {
        let target = self.file_url(id, "supportsAllDrives=true");
        let answer = self.exchange(Method::DELETE, &target, "", None).await?;
        self.shared.forget(flat);
        match answer.status {
            200 | 204 | 404 => Ok(()),
            status => Err(StorageError::Failed(format!(
                "Drive deletion of {flat} answered {status}: {}",
                String::from_utf8_lossy(&answer.body)
            ))),
        }
    }
}

/// The `id` of an answer, as `json.Unmarshal` into `struct{ID string}`.
fn parse_id(payload: &[u8]) -> Result<String, StorageError> {
    gojson::root(payload)
        .and_then(|root| gojson::string(&root, "id"))
        .map_err(|()| StorageError::Failed("failed to parse the Drive upload response".to_owned()))
}

#[async_trait]
impl Storage for DriveStorage {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError> {
        if data.len() <= INLINE_LIMIT {
            let description = base64::engine::general_purpose::STANDARD.encode(&data);
            return self.create(name, &description).await.map(|_| ());
        }
        self.put_media(name, &data).await
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let flat = flatten(name);
        let id = self.resolve_id(&flat).await?;
        let payload = match self.read_body(&id).await {
            Err(StorageError::NotFound) => {
                self.shared.forget(&flat);
                return Err(StorageError::NotFound);
            }
            other => other?,
        };
        if !payload.is_empty() {
            return Ok(payload);
        }
        self.get_inline(&id).await
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let flat = flatten(name);
        match self.resolve_id(&flat).await {
            Ok(id) => self.delete_id(&flat, &id).await?,
            Err(StorageError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let children = self
            .query(&format!(
                "name contains '{}'",
                quote_value(&format!("{flat}{FLAT_SEPARATOR}"))
            ))
            .await?;
        let mut names: Vec<&String> = children.keys().collect();
        names.sort();
        for name in names {
            self.delete_id(name, &children[name].id).await?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Entry>, StorageError> {
        let flat = format!("{}{FLAT_SEPARATOR}", flatten(prefix));
        let found = self
            .query(&format!("name contains '{}'", quote_value(&flat)))
            .await?;
        let mut names: Vec<&String> = found.keys().collect();
        names.sort();
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        for name in names {
            // Xray-core trims the prefix only when a name has it.
            let rest = name.strip_prefix(flat.as_str()).unwrap_or(name);
            if rest.is_empty() {
                continue;
            }
            let (rest, direct) = match rest.split_once(FLAT_SEPARATOR) {
                Some((first, _)) => (first, false),
                None => (rest, true),
            };
            if !seen.insert(rest.to_owned()) {
                continue;
            }
            let mut entry = Entry::named(rest);
            let file = &found[name];
            if direct && !file.description.is_empty() {
                entry.inline = base64::engine::general_purpose::STANDARD
                    .decode(&file.description)
                    .ok()
                    .map(Bytes::from);
            }
            entries.push(entry);
        }
        Ok(entries)
    }
}

#[async_trait]
impl SlotStore for DriveStorage {
    async fn make_slot(&self, name: &str) -> Result<String, StorageError> {
        let id = self.create(name, "").await?;
        if id.is_empty() {
            return Err(StorageError::Failed(format!(
                "Drive returned no id for {name}"
            )));
        }
        Ok(id)
    }

    /// `setSlot`: a description and a body in one request.
    async fn set_slot(
        &self,
        id: &str,
        description: &str,
        body: Option<Bytes>,
    ) -> Result<(), StorageError> {
        let mut payload = metadata(None, Some(description), None).into_bytes();
        let mut target = self.file_url(id, "fields=id&supportsAllDrives=true");
        let mut content_type = JSON.to_owned();
        if let Some(body) = body {
            let upload = self
                .shared
                .urls
                .upload
                .split('?')
                .next()
                .unwrap_or_default();
            target = format!(
                "{upload}/{}?uploadType=multipart&fields=id&supportsAllDrives=true",
                go_url::escape(id.as_bytes(), Encoding::PathSegment)
            );
            content_type = format!("multipart/related; boundary={BOUNDARY}");
            payload = multipart_body(&payload, &body);
        }
        let answer = self
            .exchange(
                Method::PATCH,
                &target,
                &content_type,
                Some(Bytes::from(payload)),
            )
            .await?;
        match answer.status {
            200 => Ok(()),
            404 => Err(StorageError::NotFound),
            status => Err(StorageError::Failed(format!(
                "Drive answered {status} for the update of {id}: {}",
                String::from_utf8_lossy(&answer.body)
            ))),
        }
    }

    async fn read_description(&self, id: &str) -> Result<String, StorageError> {
        let target = self.file_url(id, "fields=description&supportsAllDrives=true");
        let answer = self.exchange(Method::GET, &target, "", None).await?;
        match answer.status {
            200 => gojson::root(&answer.body)
                .and_then(|root| gojson::string(&root, "description"))
                .map_err(|()| {
                    StorageError::Failed(format!("failed to parse the description of {id}"))
                }),
            404 => Err(StorageError::NotFound),
            status => Err(StorageError::Failed(format!(
                "Drive answered {status} for the description of {id}: {}",
                String::from_utf8_lossy(&answer.body)
            ))),
        }
    }

    async fn read_body(&self, id: &str) -> Result<Bytes, StorageError> {
        let target = self.file_url(id, "alt=media&supportsAllDrives=true");
        let answer = self.exchange(Method::GET, &target, "", None).await?;
        match answer.status {
            200 => Ok(answer.body),
            404 => Err(StorageError::NotFound),
            status => Err(StorageError::Failed(format!(
                "Drive answered {status} for the body of {id}: {}",
                String::from_utf8_lossy(&answer.body)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_read_as_xray_core_reads_them() {
        assert!(rate_limited(
            br#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#
        ));
        assert!(rate_limited(
            br#"{"error":{"status":"RESOURCE_EXHAUSTED"}}"#
        ));
        assert!(!rate_limited(
            br#"{"error":{"errors":[{"reason":"forbidden"}]}}"#
        ));
        // A type that does not fit fails the whole decode, as in Go.
        assert!(!rate_limited(
            br#"{"error":{"status":5,"errors":[{"reason":"rateLimitExceeded"}]}}"#
        ));
        assert!(!rate_limited(b"not json"));
    }

    #[test]
    fn bodies_and_queries_are_spelled_as_xray_core_spells_them() {
        assert_eq!(quote_value(r"it's a\b"), r"it\'s a\\b");
        assert_eq!(
            metadata(Some("sessions~1-a"), Some("ZGF0YQ=="), Some("folder")),
            r#"{"description":"ZGF0YQ==","name":"sessions~1-a","parents":["folder"]}"#
        );
        let body = multipart_body(b"{}", b"data");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--xdrive-boundary\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--xdrive-boundary--\r\n"
        );
    }
}
