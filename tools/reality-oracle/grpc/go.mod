// A module of its own, deliberately, for the reason the masquerade oracle next
// door is one, and for a second reason of its own. The root module pins
// golang.org/x/crypto at v0.36.0, and uTLS compiled against a different
// x/crypto emits different ClientHello bytes -- enough to break the committed
// tests/fixtures/reality/clienthello_chrome_auto.json. Both requirements below
// move it: adding google.golang.org/grpc v1.82.1 to the root module selects
// a newer x/crypto through its own graph, and xray-core requires v0.54.0
// outright. Keeping this oracle out of the root module keeps the two
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
// The Xray-core requirement is release v26.7.28, commit
// 5ca6f4b7d4dc20a881d4330e498892697627ec0c.
module xray-rust-tools/grpc-oracle

go 1.26

require (
	github.com/xtls/xray-core v1.260327.1-0.20260728075948-5ca6f4b7d4dc
	golang.org/x/net v0.57.0
	google.golang.org/grpc v1.82.1
)

require (
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
