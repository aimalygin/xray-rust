module xray-rust-tools

go 1.27

// The oracles hand uTLS a deterministic crypto/rand. Since Go 1.26 a module at
// go 1.26 or later makes crypto/ecdh ignore it, which turns every key share
// and ECH GREASE key into a fresh random draw; keep the old behaviour.
godebug cryptocustomrand=1

require github.com/refraction-networking/utls v1.8.3-0.20261108164504-a13c59ffe98b

require (
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
