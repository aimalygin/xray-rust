// A module of its own, deliberately: the root module holds exactly the uTLS
// graph Xray-core builds its ClientHellos with, and importing xray-core there
// would move it with every requirement xray-core adds. Keeping this oracle out
// of the root module keeps the two dependency graphs from colliding.
//
// Run it from anywhere in the repo with `go run -C`:
//
//	go run -C tools/reality-oracle/masquerade -tags reality_oracle_masquerade_headers . -variant ws
//
// `go mod tidy` drops the requirement below, because the only file that needs it
// sits behind a build tag. Edit this file by hand.
//
// The Xray-core requirement is release v26.11.9, commit
// 676eaf66f8f05d4d558ee7a74b4736623d3feeb9.
module xray-rust-tools/masquerade-oracle

go 1.27

require github.com/xtls/xray-core v1.260327.1-0.20261109052709-676eaf66f8f0

require (
	github.com/klauspost/cpuid/v2 v2.4.2 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
