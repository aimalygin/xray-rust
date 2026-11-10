// A module of its own, deliberately, for the reason the masquerade oracle next
// door is one: the root module holds exactly the uTLS graph Xray-core builds
// its ClientHellos with, and both requirements below would move it through
// their own graphs. Keeping this oracle out of the root module keeps the two
// dependency graphs from colliding.
//
// Separate from the masquerade module as well as from the root one, because
// that module's graph is minimal on purpose: it imports only
// xray-core/common/utils, so module-graph pruning leaves it three entries in
// go.sum. Adding gRPC there would grow it to this one's size for no benefit to
// either.
//
// Run it from anywhere in the repo with `go run -C`:
//
//	go run -C tools/reality-oracle/grpc -tags reality_oracle_grpc_wire . -wire request_headers
//
// `go mod tidy` drops the requirements below, because the only file that needs
// them sits behind a build tag. Edit this file by hand.
//
// The Xray-core requirement is release v26.11.9, commit
// 676eaf66f8f05d4d558ee7a74b4736623d3feeb9.
module xray-rust-tools/grpc-oracle

go 1.27

require (
	github.com/xtls/xray-core v1.260327.1-0.20261109052709-676eaf66f8f0
	golang.org/x/net v0.62.0
	google.golang.org/grpc v1.85.0
)

require (
	github.com/yuin/gopher-lua v1.1.2 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
