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
// The Xray-core requirement is release v26.7.28, commit
// 5ca6f4b7d4dc20a881d4330e498892697627ec0c.
module xray-rust-tools/masquerade-oracle

go 1.26

require github.com/xtls/xray-core v1.260327.1-0.20260728075948-5ca6f4b7d4dc

require (
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
