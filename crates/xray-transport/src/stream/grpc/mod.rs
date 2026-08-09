//! Xray's gRPC stream transport: VLESS bytes inside `Hunk` messages on one
//! bidirectional HTTP/2 stream.

mod config;
mod framing;
mod h2client;
mod keepalive;
mod path;
mod pool;
mod stream;

pub use config::{resolve_keepalive, resolve_user_agent, Authority, GrpcConfig, GrpcKeepalive};
pub use framing::{encode_hunk, HunkDecoder, HunkMode, MAX_HUNK_PAYLOAD_LEN};
pub use h2client::open_grpc_h2_stream;
pub use path::grpc_request_path;
pub use pool::GrpcTransport;
pub use stream::GrpcStream;
