//! Xray's gRPC stream transport: VLESS bytes inside `Hunk` messages on one
//! bidirectional HTTP/2 stream.

mod framing;
mod path;

pub use framing::encode_hunk;
pub use path::grpc_request_path;
