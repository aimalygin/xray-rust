// A module of its own, deliberately: importing xray-core drags golang.org/x/crypto
// from v0.36.0 up to v0.54.0, and uTLS compiled against v0.54.0 emits different
// ClientHello bytes -- enough to break the committed
// tests/fixtures/reality/clienthello_chrome_auto.json. Keeping this oracle out
// of the root module keeps the two dependency graphs from colliding.
//
// Run it from anywhere in the repo with `go run -C`:
//
//	go run -C tools/reality-oracle/masquerade -tags reality_oracle_masquerade_headers . -variant ws
//
// `go mod tidy` drops the requirement below, because the only file that needs it
// sits behind a build tag. Edit this file by hand.
//
// The Xray-core requirement is release v26.10.31, commit
// a4a3dff5b20c2faae567b742c172c7b95e75c083.
module xray-rust-tools/masquerade-oracle

go 1.27

require github.com/xtls/xray-core v1.260327.1-0.20261031132019-a4a3dff5b20c

require (
	github.com/klauspost/cpuid/v2 v2.4.1 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
