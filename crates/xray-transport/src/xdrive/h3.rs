//! A storage over HTTP/3, as Xray-core v26.10.31's XDRIVE client reaches
//! one through quic-go's `http3.Transport` when `alpn` is exactly
//! `["h3"]`: one QUIC connection a host, set up as XHTTP's HTTP/3 dial
//! sets one up (the stream's QUIC parameters, its UDP masks, BBR, udphop),
//! and each request a stream on it with the headers Go's client writes.
//! Xray-core shapes that connection as Chrome unless `disableChromeParrot`
//! is set; this one is Quinn's own.

use std::io;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};

use super::client::{read_body, ChunkedBody, Prepared, Progress, ServiceError, ServiceResponse};
use super::h2::build_request;
use crate::stream::xhttp::H3Client;

/// The most a request's body goes in one DATA frame, as with HTTP/2.
const PROGRESS_CHUNK: usize = 16 << 10;

/// One exchange on `client`: the request, its body, and the answer read
/// up to the request's limit and one byte past it.
pub(crate) async fn send(
    client: &H3Client,
    prepared: &Prepared<'_>,
    progress: &Progress,
) -> Result<ServiceResponse, ServiceError> {
    let failed = |error: h3::error::StreamError| ServiceError::Network(format!("http3: {error}"));
    let request = build_request(prepared)?;
    let mut sender = client.request_sender();
    let mut stream = sender.send_request(request).await.map_err(failed)?;
    for chunk in prepared.request.body.chunks(PROGRESS_CHUNK) {
        stream
            .send_data(Bytes::copy_from_slice(chunk))
            .await
            .map_err(failed)?;
        progress.alive();
    }
    stream.finish().await.map_err(failed)?;
    let response = stream.recv_response().await.map_err(failed)?;
    progress.alive();
    let header = |name| {
        response
            .headers()
            .get(name)
            .map(|value: &http::HeaderValue| String::from_utf8_lossy(value.as_bytes()).into_owned())
    };
    let retry_after = header(http::header::RETRY_AFTER);
    let location = header(http::header::LOCATION);
    let gzip = prepared.gzip
        && response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"));
    let limit = prepared.request.max_body.saturating_add(1);
    let chunks = ChunkedBody::new(|cx: &mut Context<'_>| {
        let polled = ready!(stream.poll_recv_data(cx));
        Poll::Ready(match polled {
            Ok(Some(mut chunk)) => {
                progress.alive();
                Some(Ok(chunk.copy_to_bytes(chunk.remaining())))
            }
            Ok(None) => None,
            Err(error) => Some(Err(io::Error::other(format!("http3: {error}")))),
        })
    });
    let body = read_body(chunks, gzip, limit).await?;
    // A body read only up to the limit is cancelled, as quic-go's client
    // cancels one whose body was closed early.
    if body.len() >= limit {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
    Ok(ServiceResponse {
        status: response.status().as_u16(),
        retry_after,
        location,
        body: Bytes::from(body),
    })
}
