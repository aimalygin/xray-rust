//! Go 1.27's `http.Client` following redirects by its default policy, as
//! the template and token clients of Xray-core v26.10.31's XDRIVE do (its
//! S3 client takes a redirect as the answer). Each hop is a request of its
//! own, sent as the caller sends one: for a session, over the XMUX
//! connection it holds then, with the masquerade headers of that hop.

use std::future::Future;

use base64::Engine as _;
use bytes::Bytes;
use http::Method;
use xray_proxy::go_url;

use super::client::{
    canonical_header_key, ServiceError, ServiceRequest, ServiceResponse, ServiceUrl,
};

/// `defaultCheckRedirect`: the most requests one call sends.
const MAX_REQUESTS: usize = 10;

/// Headers a redirect to another domain leaves behind.
const SENSITIVE: [&str; 6] = [
    "Authorization",
    "Www-Authenticate",
    "Cookie",
    "Cookie2",
    "Proxy-Authorization",
    "Proxy-Authenticate",
];

/// Headers of the body, which a redirect that drops the body leaves behind.
const BODY: [&str; 4] = [
    "Content-Encoding",
    "Content-Language",
    "Content-Location",
    "Content-Type",
];

/// A request as `http.NewRequest` holds it: the URL parsed, not yet
/// checked for a scheme and host the transport can send to.
#[derive(Clone, Debug)]
pub(crate) struct Followed {
    pub method: Method,
    pub url: go_url::Url,
    /// As `Header.Set` leaves them: one value a name, the last one set.
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub max_body: usize,
}

/// `http.NewRequest`'s reading of a URL: `url.Parse`, then an empty port
/// dropped from the host.
pub(crate) fn new_request_url(raw: &str) -> Result<go_url::Url, String> {
    let mut url = go_url::parse(raw)?;
    if url.host.rfind(':').map(|i| i as isize).unwrap_or(-1)
        > url.host.rfind(']').map(|i| i as isize).unwrap_or(-1)
        && url.host.ends_with(':')
    {
        url.host.pop();
    }
    Ok(url)
}

/// `Header.Set` over `headers`, keys canonical.
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    let name = canonical_header_key(name);
    headers.retain(|(key, _)| *key != name);
    headers.push((name, value));
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// `redirectBehavior`: the next hop's method and whether it keeps the
/// body, or `None` when the answer is no redirect.
fn redirect_behavior(method: &Method, status: u16) -> Option<(Method, bool)> {
    match status {
        301..=303 => {
            let next = if *method == Method::GET || *method == Method::HEAD {
                method.clone()
            } else {
                Method::GET
            };
            Some((next, false))
        }
        // Every body here can be sent again, as `GetBody` of a
        // `bytes.Reader` makes it.
        307 | 308 => Some((method.clone(), true)),
        _ => None,
    }
}

/// `httpguts.PunycodeHostPort` and `ascii.ToLower` of a hostname; a name
/// that is not ASCII is not compared here, which only ever strips more.
fn canonical_host(url: &go_url::Url) -> Option<String> {
    let host = url.hostname();
    host.is_ascii().then(|| host.to_ascii_lowercase())
}

/// `isDomainOrSubdomain`.
fn is_domain_or_subdomain(sub: &str, parent: &str) -> bool {
    if sub == parent {
        return true;
    }
    if sub.contains([':', '%']) {
        return false;
    }
    sub.len() > parent.len()
        && sub.ends_with(parent)
        && sub.as_bytes()[sub.len() - parent.len() - 1] == b'.'
}

/// `shouldCopyHeaderOnRedirect`: whether `dest` is the initial host or a
/// subdomain of it.
fn should_copy_header_on_redirect(initial: &go_url::Url, dest: &go_url::Url) -> bool {
    match (canonical_host(initial), canonical_host(dest)) {
        (Some(initial), Some(dest)) => is_domain_or_subdomain(&dest, &initial),
        _ => false,
    }
}

/// `refererForURL`: the last URL without its user information, nothing
/// from `https` to `http`, a Referer set by the caller as it is.
fn referer_for(last: &go_url::Url, next: &go_url::Url, explicit: Option<&str>) -> Option<String> {
    if last.scheme == "https" && next.scheme == "http" {
        return None;
    }
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        return Some(explicit.to_owned());
    }
    let mut referer = last.to_go_string();
    if last.user.is_some() {
        referer = referer.replacen(&format!("{}@", last.user_string()), "", 1);
    }
    Some(referer)
}

/// `Client.Do`: sends `initial` through `send`, then each redirect its
/// answers give, up to ten requests in all. An answer that is no redirect,
/// or one without a `Location`, is the answer.
pub(crate) async fn follow<F, Fut>(
    initial: Followed,
    mut send: F,
) -> Result<ServiceResponse, ServiceError>
where
    F: FnMut(ServiceRequest) -> Fut,
    Fut: Future<Output = Result<ServiceResponse, ServiceError>>,
{
    let mut initial_headers = Vec::with_capacity(initial.headers.len());
    for (name, value) in &initial.headers {
        set_header(&mut initial_headers, name, value.clone());
    }
    let mut method = initial.method.clone();
    let mut url = initial.url.clone();
    let mut headers = initial_headers.clone();
    let mut body = initial.body.clone();
    let mut include_body = true;
    let mut strip_sensitive = false;
    let mut sent = 0;
    loop {
        // `Client.send`: the URL's user information as Basic auth, unless the
        // request carries an Authorization of its own.
        if let Some(user) = &url.user {
            if header(&headers, "Authorization").is_none() {
                let mut pair = user.username.clone();
                pair.push(b':');
                pair.extend_from_slice(user.password.as_deref().unwrap_or_default());
                let basic = base64::engine::general_purpose::STANDARD.encode(&pair);
                set_header(&mut headers, "Authorization", format!("Basic {basic}"));
            }
        }
        let request = ServiceRequest {
            method: method.clone(),
            url: ServiceUrl::from_go(&url)?,
            headers: std::mem::take(&mut headers),
            body: std::mem::take(&mut body),
            max_body: initial.max_body,
        };
        let answer = send(request).await?;
        sent += 1;
        let Some((next_method, keeps_body)) = redirect_behavior(&method, answer.status) else {
            return Ok(answer);
        };
        // Once a hop drops the body, no later one sends it.
        include_body &= keeps_body;
        let Some(location) = answer
            .location
            .as_deref()
            .filter(|location| !location.is_empty())
        else {
            return Ok(answer);
        };
        let next = url.parse_reference(location).map_err(|error| {
            ServiceError::Request(format!(
                "failed to parse Location header {location:?}: {error}"
            ))
        })?;
        if !strip_sensitive
            && initial.url.host != next.host
            && !should_copy_header_on_redirect(&initial.url, &next)
        {
            strip_sensitive = true;
        }
        headers = initial_headers
            .iter()
            .filter(|(name, _)| {
                let sensitive = strip_sensitive && SENSITIVE.contains(&name.as_str());
                let of_body = !include_body && BODY.contains(&name.as_str());
                !(sensitive || of_body)
            })
            .cloned()
            .collect();
        if let Some(referer) = referer_for(&url, &next, header(&headers, "Referer")) {
            set_header(&mut headers, "Referer", referer);
        }
        if sent >= MAX_REQUESTS {
            return Err(ServiceError::Request(format!(
                "{location:?}: stopped after 10 redirects"
            )));
        }
        body = if include_body {
            initial.body.clone()
        } else {
            Bytes::new()
        };
        method = next_method;
        url = next;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn answer(status: u16, location: Option<&str>) -> ServiceResponse {
        ServiceResponse {
            status,
            location: location.map(str::to_owned),
            ..ServiceResponse::default()
        }
    }

    /// Sends `initial` against a list of answers, returning what each hop
    /// sent and the final result.
    async fn run(
        initial: Followed,
        answers: Vec<ServiceResponse>,
    ) -> (Vec<ServiceRequest>, Result<ServiceResponse, ServiceError>) {
        let sent = Mutex::new(Vec::new());
        let answers = Mutex::new(answers.into_iter());
        let result = follow(initial, |request| {
            sent.lock().unwrap().push(request);
            let next = answers.lock().unwrap().next().expect("an answer per hop");
            async move { Ok(next) }
        })
        .await;
        (sent.into_inner().unwrap(), result)
    }

    fn put(url: &str) -> Followed {
        Followed {
            method: Method::PUT,
            url: go_url::parse(url).unwrap(),
            headers: vec![
                ("authorization".to_owned(), "Bearer t".to_owned()),
                (
                    "Content-Type".to_owned(),
                    "application/octet-stream".to_owned(),
                ),
                ("X-Custom".to_owned(), "1".to_owned()),
            ],
            body: Bytes::from_static(b"data"),
            max_body: 1,
        }
    }

    fn names(request: &ServiceRequest) -> Vec<&str> {
        let mut names: Vec<&str> = request.headers.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        names
    }

    #[tokio::test]
    async fn see_other_drops_the_body_and_its_headers() {
        let (sent, result) = run(
            put("https://api.example/v1/put"),
            vec![answer(303, Some("/v1/done?x=1")), answer(200, None)],
        )
        .await;
        assert_eq!(result.unwrap().status, 200);
        assert_eq!(sent[1].method, Method::GET);
        assert!(sent[1].body.is_empty());
        assert_eq!(sent[1].url.target, "/v1/done?x=1");
        // Same host: Authorization stays; Content-Type goes with the body.
        assert_eq!(names(&sent[1]), ["Authorization", "Referer", "X-Custom"]);
        assert_eq!(
            header(&sent[1].headers, "Referer"),
            Some("https://api.example/v1/put")
        );
    }

    #[tokio::test]
    async fn temporary_redirects_keep_method_and_body_and_strip_auth_off_domain() {
        let (sent, result) = run(
            put("https://api.example/v1/put"),
            vec![
                answer(307, Some("https://cdn.api.example/blob")),
                answer(308, Some("https://other.example/blob")),
                answer(201, None),
            ],
        )
        .await;
        assert_eq!(result.unwrap().status, 201);
        assert_eq!(sent[1].method, Method::PUT);
        assert_eq!(sent[1].body, Bytes::from_static(b"data"));
        // A subdomain keeps Authorization, another domain does not, and it
        // stays stripped after.
        assert!(header(&sent[1].headers, "Authorization").is_some());
        assert_eq!(header(&sent[2].headers, "Authorization"), None);
        assert_eq!(
            header(&sent[2].headers, "Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(sent[2].url.hostname, "other.example");
    }

    #[tokio::test]
    async fn no_location_or_no_redirect_is_the_answer() {
        let (sent, result) = run(put("http://h/x"), vec![answer(302, None)]).await;
        assert_eq!((sent.len(), result.unwrap().status), (1, 302));
        let (sent, result) = run(put("http://h/x"), vec![answer(304, Some("/y"))]).await;
        assert_eq!((sent.len(), result.unwrap().status), (1, 304));
    }

    #[tokio::test]
    async fn ten_requests_at_most_and_no_referer_down_to_http() {
        let answers = (0..10)
            .map(|_| answer(302, Some("http://h/loop")))
            .collect();
        let (sent, result) = run(put("https://h/start"), answers).await;
        assert_eq!(sent.len(), 10);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("stopped after 10 redirects"));
        assert_eq!(header(&sent[1].headers, "Referer"), None);
        assert_eq!(header(&sent[2].headers, "Referer"), Some("http://h/loop"));
    }

    #[tokio::test]
    async fn bad_locations_and_targets_fail() {
        let (_, result) = run(put("http://h/x"), vec![answer(302, Some("http://[::1"))]).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to parse Location header"));
        let (_, result) = run(put("http://h/x"), vec![answer(302, Some("ftp://h/y"))]).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported protocol scheme"));
    }

    #[test]
    fn referers_drop_user_information() {
        let last = go_url::parse("https://u:p@h/a#f").unwrap();
        let next = go_url::parse("https://h/b").unwrap();
        assert_eq!(
            referer_for(&last, &next, None).as_deref(),
            Some("https://h/a#f")
        );
        assert_eq!(referer_for(&last, &next, Some("x")).as_deref(), Some("x"));
        assert!(is_domain_or_subdomain("a.b.c", "b.c"));
        assert!(!is_domain_or_subdomain("ab.c", "b.c"));
        assert!(!is_domain_or_subdomain("::1", "1"));
    }
}
