//! XHTTP wire engines.

mod config;
mod h1;
mod h2;
mod h3;
mod padding;
mod request;
mod transport;

pub use config::{
    XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpMetadataPlacement, XhttpMode,
    XhttpModeSelection, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpRange, XhttpScheme,
    XhttpUplinkDataPlacement,
};
pub use h3::{H3Congestion, H3QuicConfig, H3QuicVersion, H3UdpHopConfig};
pub use transport::{XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy};

/// Internal HTTP/1.1 engine surface used by XHTTP orchestration and focused
/// integration tests. This is not a standalone HTTP client API.
#[doc(hidden)]
pub mod test_only {
    pub use super::h1::{
        send_fixed_request, start_chunked_request, start_fixed_request, ChunkedUpload, H1Error,
        H1Request, H1ResponseBody, PendingResponse, DEFAULT_MAX_RESPONSE_HEAD_BYTES,
    };
}

/// HTTP/2 engine test surface. Production orchestration imports concrete
/// pieces from this private module once its mode dispatch is wired.
#[doc(hidden)]
pub mod h2_test_only {
    pub use super::h2::{connect_h2, connect_h2_with_keepalive, H2Client, H2Error};
}

/// HTTP/3 engine test surface. Production orchestration imports concrete
/// pieces from this private module once its UDP mode dispatch is wired.
#[doc(hidden)]
pub mod h3_test_only {
    pub use super::h3::{
        connect_h3, connect_h3_candidates, H3Client, H3Congestion, H3ConnectConfig, H3Diagnostics,
        H3Error, H3PendingResponse, H3QuicConfig, H3QuicVersion, H3ResponseBody, H3UdpHopConfig,
        H3Upload,
    };
}

#[doc(hidden)]
pub mod transport_test_only {
    pub use super::transport::{
        XhttpClock, XhttpDial, XhttpH3Dial, XhttpH3DialFuture, XhttpHttpVersion, XhttpTransport,
        XhttpTransportError, XhttpXmuxPolicy,
    };
}

#[doc(hidden)]
pub mod composer_test_only {
    pub use super::config::{
        NormalizedRange, XhttpConfig, XhttpConfigError, XhttpConfigInput, XhttpEndpoint,
        XhttpMetadataConfig, XhttpMetadataPlacement, XhttpMode, XhttpModeSelection,
        XhttpPaddingConfig, XhttpPaddingMethod, XhttpPaddingPlacement, XhttpRange, XhttpScheme,
        XhttpUplinkDataConfig, XhttpUplinkDataPlacement,
    };
    pub use super::padding::{draw_range, generate_padding, PaddingError};
    pub use super::request::{
        compose_packet_request, compose_stream_request, XhttpRequest, XhttpRequestBody,
        XhttpRequestError, XhttpStreamBody,
    };
}
