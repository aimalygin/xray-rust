//! Xray's gRPC stream transport: VLESS bytes inside `Hunk` messages on one
//! bidirectional HTTP/2 stream.

mod path;

pub use path::grpc_request_path;
