//! Xray's gRPC stream transport: VLESS bytes inside `Hunk` messages on one
//! bidirectional HTTP/2 stream.

mod config;
mod framing;
mod h2client;
mod path;
mod stream;

pub use config::{resolve_user_agent, GrpcConfig};
pub use framing::{encode_hunk, HunkDecoder, MAX_HUNK_PAYLOAD_LEN};
pub use h2client::open_grpc_h2_stream;
pub use path::grpc_request_path;
pub use stream::GrpcStream;
