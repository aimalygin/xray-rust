# REALITY Oracle Handshake Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic Xray-core-compatible REALITY session-id oracle fixtures, Rust primitive tests, and a sealed ClientHello patcher without enabling live REALITY networking.

**Architecture:** `xray-transport::reality` owns pure deterministic REALITY sealing primitives. A small Go standard-library oracle produces committed JSON fixtures, and Rust tests consume those fixtures to lock compatibility. `RealityConnector` remains a non-network boundary, and `TransportDialer` continues to reject REALITY configs.

**Tech Stack:** Rust 2021, `aes-gcm`, `hkdf`, `sha2`, `zeroize`, `serde_json` test fixtures, Go 1.23 standard library oracle helper.

---

## File Structure

- `Cargo.toml`: add the workspace `zeroize` dependency.
- `crates/xray-transport/Cargo.toml`: add production `zeroize` and test-only `serde`/`serde_json`.
- `tools/reality-oracle/session_id_vectors.go`: generate and check deterministic REALITY session-id JSON fixtures.
- `tests/fixtures/reality/session_id_vectors.json`: committed oracle vectors consumed by Rust tests.
- `crates/xray-transport/src/reality.rs`: replace the current truncating primitive with explicit input, validation, detached AES-GCM sealing, zeroized auth key, and ClientHello patching.
- `crates/xray-transport/tests/reality_tests.rs`: replace hard-coded Rust-only expectations with fixture-driven compatibility tests and negative coverage.
- `crates/xray-transport/src/reality_connector.rs`: update boundary docs to point at the new pure sealing API.
- `docs/verification.md`: add the REALITY primitive oracle check command.

---

### Task 1: Add Oracle Helper, Fixtures, And Dependencies

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/xray-transport/Cargo.toml`
- Create: `tools/reality-oracle/session_id_vectors.go`
- Create: `tests/fixtures/reality/session_id_vectors.json`

- [ ] **Step 1: Add dependencies**

Modify the workspace dependencies in `Cargo.toml`:

```toml
[workspace.dependencies]
aes-gcm = "0.10"
async-trait = "0.1"
bytes = "1"
hkdf = "0.12"
libc = "0.2"
prost = "0.13"
rand = "0.8"
rcgen = { version = "0.14", default-features = false, features = ["ring"] }
rustls = { version = "0.23", default-features = false, features = ["logging", "ring", "std", "tls12"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
thiserror = "2"
tokio = { version = "1", features = ["io-util", "macros", "net", "rt", "rt-multi-thread", "sync", "time"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["logging", "ring", "tls12"] }
uuid = { version = "1", features = ["serde", "v4"] }
webpki-roots = "1"
x25519-dalek = { version = "2", features = ["static_secrets"] }
zeroize = "1"
```

Modify `crates/xray-transport/Cargo.toml`:

```toml
[dependencies]
aes-gcm.workspace = true
async-trait.workspace = true
hkdf.workspace = true
rustls.workspace = true
sha2.workspace = true
thiserror.workspace = true
tokio.workspace = true
tokio-rustls.workspace = true
webpki-roots.workspace = true
x25519-dalek.workspace = true
xray-routing = { path = "../xray-routing" }
zeroize.workspace = true

[dev-dependencies]
rcgen.workspace = true
serde.workspace = true
serde_json.workspace = true
```

- [ ] **Step 2: Create the Go oracle helper**

Create `tools/reality-oracle/session_id_vectors.go`:

```go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type vector struct {
	Name                       string `json:"name"`
	VersionHex                 string `json:"version_hex"`
	UnixTime                  uint32 `json:"unix_time"`
	ShortIDHex                string `json:"short_id_hex"`
	SharedSecretHex           string `json:"shared_secret_hex"`
	HelloRandomHex            string `json:"hello_random_hex"`
	SessionIDOffset           int    `json:"session_id_offset"`
	RawClientHelloBeforeHex   string `json:"raw_client_hello_before_hex"`
	ExpectedSessionIDHex      string `json:"expected_session_id_hex"`
	ExpectedClientHelloAfterHex string `json:"expected_client_hello_after_hex"`
}

type input struct {
	name             string
	version          []byte
	unixTime         uint32
	shortID          []byte
	sharedSecret     []byte
	helloRandom      []byte
	sessionIDOffset  int
	rawClientHello   []byte
}

func main() {
	checkPath := flag.String("check", "", "compare generated vectors with a committed JSON fixture")
	flag.Parse()

	generated, err := json.MarshalIndent(buildVectors(), "", "  ")
	if err != nil {
		panic(err)
	}
	generated = append(generated, '\n')

	if *checkPath == "" {
		_, _ = os.Stdout.Write(generated)
		return
	}

	expected, err := os.ReadFile(*checkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(expected, generated) {
		fmt.Fprintf(os.Stderr, "fixture mismatch: %s\n", *checkPath)
		os.Exit(1)
	}
}

func buildVectors() []vector {
	return []vector{
		buildVector(input{
			name:            "xray_offset_39_short_id_4",
			version:         []byte{26, 5, 9},
			unixTime:        1700000000,
			shortID:         []byte{2, 3, 4, 5},
			sharedSecret:    repeat(0x07, 32),
			helloRandom:     append(repeat(0x09, 20), repeat(0x0b, 12)...),
			sessionIDOffset: 39,
			rawClientHello:  xrayOffset39ClientHello(),
		}),
		buildVector(input{
			name:            "explicit_offset_13_short_id_8",
			version:         []byte{1, 2, 3},
			unixTime:        42,
			shortID:         []byte{0, 1, 2, 3, 4, 5, 6, 7},
			sharedSecret:    sequence(0x00, 32),
			helloRandom:     sequence(0x20, 32),
			sessionIDOffset: 13,
			rawClientHello:  offset13ClientHello(),
		}),
	}
}

func buildVector(in input) vector {
	sessionID := sealSessionID(in.version, in.unixTime, in.shortID, in.sharedSecret, in.helloRandom, in.rawClientHello)
	patched := append([]byte(nil), in.rawClientHello...)
	copy(patched[in.sessionIDOffset:in.sessionIDOffset+32], sessionID)

	return vector{
		Name:                       in.name,
		VersionHex:                 hex.EncodeToString(in.version),
		UnixTime:                  in.unixTime,
		ShortIDHex:                hex.EncodeToString(in.shortID),
		SharedSecretHex:           hex.EncodeToString(in.sharedSecret),
		HelloRandomHex:            hex.EncodeToString(in.helloRandom),
		SessionIDOffset:           in.sessionIDOffset,
		RawClientHelloBeforeHex:   hex.EncodeToString(in.rawClientHello),
		ExpectedSessionIDHex:      hex.EncodeToString(sessionID),
		ExpectedClientHelloAfterHex: hex.EncodeToString(patched),
	}
}

func sealSessionID(version []byte, unixTime uint32, shortID []byte, sharedSecret []byte, helloRandom []byte, rawClientHello []byte) []byte {
	prefix := make([]byte, 16)
	copy(prefix[0:3], version)
	binary.BigEndian.PutUint32(prefix[4:8], unixTime)
	copy(prefix[8:16], shortID)

	authKey := hkdfSha256(sharedSecret, helloRandom[:20], []byte("REALITY"), 32)
	block, err := aes.NewCipher(authKey)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, helloRandom[20:32], prefix, rawClientHello)
}

func hkdfSha256(secret []byte, salt []byte, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)

	var okm []byte
	var previous []byte
	counter := byte(1)
	for len(okm) < length {
		expand := hmac.New(sha256.New, prk)
		expand.Write(previous)
		expand.Write(info)
		expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		okm = append(okm, previous...)
		counter++
	}

	return okm[:length]
}

func xrayOffset39ClientHello() []byte {
	raw := []byte{0x16, 0x03, 0x01, 0x00, 0x4b, 0x01, 0x00, 0x00, 0x47, 0x03, 0x03}
	raw = append(raw, sequence(0xa0, 28)...)
	raw = append(raw, repeat(0x00, 32)...)
	raw = append(raw, sequence(0xe0, 12)...)
	return raw
}

func offset13ClientHello() []byte {
	raw := sequence(0x30, 13)
	raw = append(raw, repeat(0x00, 32)...)
	raw = append(raw, sequence(0x70, 19)...)
	return raw
}

func repeat(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func sequence(start byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
```

- [ ] **Step 3: Run the helper before adding the fixture**

Run:

```bash
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

Expected: FAIL with a message containing `read fixture`, because the fixture file does not exist yet.

- [ ] **Step 4: Add the committed fixture**

Create `tests/fixtures/reality/session_id_vectors.json`:

```json
[
  {
    "name": "xray_offset_39_short_id_4",
    "version_hex": "1a0509",
    "unix_time": 1700000000,
    "short_id_hex": "02030405",
    "shared_secret_hex": "0707070707070707070707070707070707070707070707070707070707070707",
    "hello_random_hex": "09090909090909090909090909090909090909090b0b0b0b0b0b0b0b0b0b0b0b",
    "session_id_offset": 39,
    "raw_client_hello_before_hex": "160301004b010000470303a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babb0000000000000000000000000000000000000000000000000000000000000000e0e1e2e3e4e5e6e7e8e9eaeb",
    "expected_session_id_hex": "e57588cf108c612231de7c33b4934e21626651b34576a2a76a57b67034b7c8fe",
    "expected_client_hello_after_hex": "160301004b010000470303a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbe57588cf108c612231de7c33b4934e21626651b34576a2a76a57b67034b7c8fee0e1e2e3e4e5e6e7e8e9eaeb"
  },
  {
    "name": "explicit_offset_13_short_id_8",
    "version_hex": "010203",
    "unix_time": 42,
    "short_id_hex": "0001020304050607",
    "shared_secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "hello_random_hex": "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "session_id_offset": 13,
    "raw_client_hello_before_hex": "303132333435363738393a3b3c0000000000000000000000000000000000000000000000000000000000000000707172737475767778797a7b7c7d7e7f808182",
    "expected_session_id_hex": "00d5e975f0fdb08abb6b075d0725a20d19190e04e4e57d4e4ce5bc8a3db64c60",
    "expected_client_hello_after_hex": "303132333435363738393a3b3c00d5e975f0fdb08abb6b075d0725a20d19190e04e4e57d4e4ce5bc8a3db64c60707172737475767778797a7b7c7d7e7f808182"
  }
]
```

- [ ] **Step 5: Verify the fixture matches the oracle helper**

Run:

```bash
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

Expected: PASS with no output.

- [ ] **Step 6: Format Go helper**

Run:

```bash
gofmt -w tools/reality-oracle/session_id_vectors.go
```

Expected: the command exits successfully.

- [ ] **Step 7: Commit oracle assets**

Run:

```bash
git add Cargo.toml crates/xray-transport/Cargo.toml tools/reality-oracle/session_id_vectors.go tests/fixtures/reality/session_id_vectors.json
git commit -m "test(transport): add reality oracle fixtures"
```

---

### Task 2: Refactor Session-ID Sealing Primitive

**Files:**
- Modify: `crates/xray-transport/tests/reality_tests.rs`
- Modify: `crates/xray-transport/src/reality.rs`

- [ ] **Step 1: Replace session-id tests with fixture-driven coverage**

Replace `crates/xray-transport/tests/reality_tests.rs` with:

```rust
mod reality_tests {
    use serde::Deserialize;
    use xray_transport::reality::{
        build_reality_session_id, RealityError, RealitySessionIdInput,
    };

    #[derive(Debug, Deserialize)]
    struct RealityVector {
        name: String,
        version_hex: String,
        unix_time: u32,
        short_id_hex: String,
        shared_secret_hex: String,
        hello_random_hex: String,
        session_id_offset: usize,
        raw_client_hello_before_hex: String,
        expected_session_id_hex: String,
        expected_client_hello_after_hex: String,
    }

    fn vectors() -> Vec<RealityVector> {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/reality/session_id_vectors.json"
        ))
        .expect("parse REALITY oracle vectors")
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input length must be even");
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex pair is utf-8");
                u8::from_str_radix(text, 16).expect("hex pair decodes")
            })
            .collect()
    }

    fn decode_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = decode_hex(hex);
        bytes
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
    }

    fn input_from_vector(vector: &RealityVector) -> RealitySessionIdInput {
        RealitySessionIdInput {
            version: decode_array::<3>(&vector.version_hex),
            unix_time: vector.unix_time,
            short_id: decode_hex(&vector.short_id_hex),
            shared_secret: decode_array::<32>(&vector.shared_secret_hex),
            hello_random: decode_array::<32>(&vector.hello_random_hex),
        }
    }

    #[test]
    fn reality_session_id_matches_oracle_vectors() {
        for vector in vectors() {
            let input = input_from_vector(&vector);
            let raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
            let expected = decode_array::<32>(&vector.expected_session_id_hex);

            let sealed = build_reality_session_id(&input, &raw_client_hello)
                .unwrap_or_else(|err| panic!("{} failed: {err}", vector.name));

            assert_eq!(sealed, expected, "{}", vector.name);
        }
    }

    #[test]
    fn reality_session_id_changes_when_aad_changes() {
        let vector = vectors().remove(0);
        let input = input_from_vector(&vector);
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let baseline = build_reality_session_id(&input, &raw_client_hello).unwrap();

        raw_client_hello[0] ^= 0xff;
        let changed = build_reality_session_id(&input, &raw_client_hello).unwrap();

        assert_ne!(baseline, changed);
    }

    #[test]
    fn reality_session_id_changes_when_nonce_changes() {
        let vector = vectors().remove(0);
        let mut input = input_from_vector(&vector);
        let raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let baseline = build_reality_session_id(&input, &raw_client_hello).unwrap();

        input.hello_random[20] ^= 0xff;
        let changed = build_reality_session_id(&input, &raw_client_hello).unwrap();

        assert_ne!(baseline, changed);
    }

    #[test]
    fn reality_short_id_lengths_zero_and_eight_are_accepted() {
        let vector = vectors().remove(1);
        let raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let mut input = input_from_vector(&vector);

        input.short_id.clear();
        build_reality_session_id(&input, &raw_client_hello).expect("empty short id is valid");

        input.short_id = vec![0, 1, 2, 3, 4, 5, 6, 7];
        build_reality_session_id(&input, &raw_client_hello).expect("8-byte short id is valid");
    }

    #[test]
    fn reality_short_id_longer_than_eight_is_rejected() {
        let vector = vectors().remove(0);
        let raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let mut input = input_from_vector(&vector);
        input.short_id = vec![0; 9];

        let err = build_reality_session_id(&input, &raw_client_hello).unwrap_err();

        assert_eq!(err, RealityError::ShortIdTooLong);
    }
}
```

- [ ] **Step 2: Run tests to verify the API is missing**

Run:

```bash
cargo test -p xray-transport reality_tests
```

Expected: FAIL with unresolved import errors for `RealitySessionIdInput` and the new two-argument `build_reality_session_id` signature.

- [ ] **Step 3: Implement the session-id primitive**

Replace `crates/xray-transport/src/reality.rs` with:

```rust
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const REALITY_INFO: &[u8] = b"REALITY";
const SHORT_ID_MAX_LEN: usize = 8;
const SESSION_ID_PREFIX_LEN: usize = 16;
const SESSION_ID_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySessionIdInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("reality short id cannot exceed 8 bytes")]
    ShortIdTooLong,
    #[error("client hello session id range {offset}..{end} is out of bounds for {len} bytes")]
    InvalidSessionIdRange {
        offset: usize,
        end: usize,
        len: usize,
    },
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
}

pub fn build_reality_session_id(
    input: &RealitySessionIdInput,
    raw_client_hello_before_seal: &[u8],
) -> Result<[u8; SESSION_ID_LEN], RealityError> {
    let mut plaintext = build_session_id_prefix(input)?;
    let mut auth_key = Zeroizing::new([0u8; 32]);
    let hkdf = Hkdf::<Sha256>::new(Some(&input.hello_random[..20]), &input.shared_secret);
    hkdf.expand(REALITY_INFO, auth_key.as_mut())
        .map_err(|_| RealityError::Hkdf)?;

    let cipher = Aes256Gcm::new_from_slice(auth_key.as_ref()).map_err(|_| RealityError::Aead)?;
    let nonce = Nonce::from_slice(&input.hello_random[20..]);
    let tag = cipher
        .encrypt_in_place_detached(nonce, raw_client_hello_before_seal, &mut plaintext)
        .map_err(|_| RealityError::Aead)?;

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id[..SESSION_ID_PREFIX_LEN].copy_from_slice(&plaintext);
    session_id[SESSION_ID_PREFIX_LEN..].copy_from_slice(&tag);
    Ok(session_id)
}

fn build_session_id_prefix(
    input: &RealitySessionIdInput,
) -> Result<[u8; SESSION_ID_PREFIX_LEN], RealityError> {
    if input.short_id.len() > SHORT_ID_MAX_LEN {
        return Err(RealityError::ShortIdTooLong);
    }

    let mut prefix = [0u8; SESSION_ID_PREFIX_LEN];
    prefix[..3].copy_from_slice(&input.version);
    prefix[4..8].copy_from_slice(&input.unix_time.to_be_bytes());
    prefix[8..8 + input.short_id.len()].copy_from_slice(&input.short_id);
    Ok(prefix)
}
```

- [ ] **Step 4: Run session-id tests**

Run:

```bash
cargo test -p xray-transport reality_tests
```

Expected: PASS for all tests in `reality_tests`.

- [ ] **Step 5: Commit session-id primitive**

Run:

```bash
git add crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): validate reality session id oracle"
```

---

### Task 3: Add ClientHello Sealing And Patching

**Files:**
- Modify: `crates/xray-transport/tests/reality_tests.rs`
- Modify: `crates/xray-transport/src/reality.rs`

- [ ] **Step 1: Add patcher tests**

Append these tests inside the existing `mod reality_tests` block in `crates/xray-transport/tests/reality_tests.rs`:

```rust
    use xray_transport::reality::{seal_reality_client_hello, RealityClientHelloPatch};

    #[test]
    fn reality_client_hello_patch_matches_oracle_vectors() {
        for vector in vectors() {
            let input = input_from_vector(&vector);
            let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
            let expected_session_id = decode_array::<32>(&vector.expected_session_id_hex);
            let expected_client_hello = decode_hex(&vector.expected_client_hello_after_hex);

            let sealed = seal_reality_client_hello(
                &input,
                RealityClientHelloPatch {
                    session_id_offset: vector.session_id_offset,
                },
                &mut raw_client_hello,
            )
            .unwrap_or_else(|err| panic!("{} failed: {err}", vector.name));

            assert_eq!(sealed, expected_session_id, "{}", vector.name);
            assert_eq!(raw_client_hello, expected_client_hello, "{}", vector.name);
        }
    }

    #[test]
    fn reality_client_hello_patch_zeroes_session_id_before_sealing() {
        let vector = vectors().remove(0);
        let input = input_from_vector(&vector);
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let range = vector.session_id_offset..vector.session_id_offset + 32;
        raw_client_hello[range.clone()].fill(0xaa);
        let expected_client_hello = decode_hex(&vector.expected_client_hello_after_hex);

        seal_reality_client_hello(
            &input,
            RealityClientHelloPatch {
                session_id_offset: vector.session_id_offset,
            },
            &mut raw_client_hello,
        )
        .unwrap();

        assert_eq!(raw_client_hello, expected_client_hello);
    }

    #[test]
    fn reality_client_hello_patch_rejects_invalid_offsets() {
        let vector = vectors().remove(0);
        let input = input_from_vector(&vector);
        let mut raw_client_hello = decode_hex(&vector.raw_client_hello_before_hex);
        let invalid_offset = raw_client_hello.len() - 31;

        let err = seal_reality_client_hello(
            &input,
            RealityClientHelloPatch {
                session_id_offset: invalid_offset,
            },
            &mut raw_client_hello,
        )
        .unwrap_err();

        assert_eq!(
            err,
            RealityError::InvalidSessionIdRange {
                offset: invalid_offset,
                end: invalid_offset + 32,
                len: raw_client_hello.len(),
            }
        );
    }
```

Then merge the two `use xray_transport::reality` imports at the top of the module so the final import block is:

```rust
    use serde::Deserialize;
    use xray_transport::reality::{
        build_reality_session_id, seal_reality_client_hello, RealityClientHelloPatch,
        RealityError, RealitySessionIdInput,
    };
```

- [ ] **Step 2: Run tests to verify the patcher is missing**

Run:

```bash
cargo test -p xray-transport reality_tests
```

Expected: FAIL with unresolved import errors for `seal_reality_client_hello` and `RealityClientHelloPatch`.

- [ ] **Step 3: Implement the patcher**

Update `crates/xray-transport/src/reality.rs` to this final content:

```rust
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const REALITY_INFO: &[u8] = b"REALITY";
const SHORT_ID_MAX_LEN: usize = 8;
const SESSION_ID_PREFIX_LEN: usize = 16;
const SESSION_ID_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySessionIdInput {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub hello_random: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityClientHelloPatch {
    pub session_id_offset: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    #[error("reality short id cannot exceed 8 bytes")]
    ShortIdTooLong,
    #[error("client hello session id range {offset}..{end} is out of bounds for {len} bytes")]
    InvalidSessionIdRange {
        offset: usize,
        end: usize,
        len: usize,
    },
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("aead seal failed")]
    Aead,
}

pub fn build_reality_session_id(
    input: &RealitySessionIdInput,
    raw_client_hello_before_seal: &[u8],
) -> Result<[u8; SESSION_ID_LEN], RealityError> {
    let mut plaintext = build_session_id_prefix(input)?;
    let mut auth_key = Zeroizing::new([0u8; 32]);
    let hkdf = Hkdf::<Sha256>::new(Some(&input.hello_random[..20]), &input.shared_secret);
    hkdf.expand(REALITY_INFO, auth_key.as_mut())
        .map_err(|_| RealityError::Hkdf)?;

    let cipher = Aes256Gcm::new_from_slice(auth_key.as_ref()).map_err(|_| RealityError::Aead)?;
    let nonce = Nonce::from_slice(&input.hello_random[20..]);
    let tag = cipher
        .encrypt_in_place_detached(nonce, raw_client_hello_before_seal, &mut plaintext)
        .map_err(|_| RealityError::Aead)?;

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id[..SESSION_ID_PREFIX_LEN].copy_from_slice(&plaintext);
    session_id[SESSION_ID_PREFIX_LEN..].copy_from_slice(&tag);
    Ok(session_id)
}

pub fn seal_reality_client_hello(
    input: &RealitySessionIdInput,
    patch: RealityClientHelloPatch,
    raw_client_hello: &mut [u8],
) -> Result<[u8; SESSION_ID_LEN], RealityError> {
    let end = patch
        .session_id_offset
        .checked_add(SESSION_ID_LEN)
        .ok_or(RealityError::InvalidSessionIdRange {
            offset: patch.session_id_offset,
            end: usize::MAX,
            len: raw_client_hello.len(),
        })?;

    if end > raw_client_hello.len() {
        return Err(RealityError::InvalidSessionIdRange {
            offset: patch.session_id_offset,
            end,
            len: raw_client_hello.len(),
        });
    }

    raw_client_hello[patch.session_id_offset..end].fill(0);
    let session_id = build_reality_session_id(input, raw_client_hello)?;
    raw_client_hello[patch.session_id_offset..end].copy_from_slice(&session_id);
    Ok(session_id)
}

fn build_session_id_prefix(
    input: &RealitySessionIdInput,
) -> Result<[u8; SESSION_ID_PREFIX_LEN], RealityError> {
    if input.short_id.len() > SHORT_ID_MAX_LEN {
        return Err(RealityError::ShortIdTooLong);
    }

    let mut prefix = [0u8; SESSION_ID_PREFIX_LEN];
    prefix[..3].copy_from_slice(&input.version);
    prefix[4..8].copy_from_slice(&input.unix_time.to_be_bytes());
    prefix[8..8 + input.short_id.len()].copy_from_slice(&input.short_id);
    Ok(prefix)
}
```

- [ ] **Step 4: Run patcher tests**

Run:

```bash
cargo test -p xray-transport reality_tests
```

Expected: PASS for all `reality_tests`.

- [ ] **Step 5: Run focused transport tests**

Run:

```bash
cargo test -p xray-transport
```

Expected: PASS. In this sandbox, tests that bind loopback may require escalated permission.

- [ ] **Step 6: Commit ClientHello patcher**

Run:

```bash
git add crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs
git commit -m "feat(transport): patch reality client hello session id"
```

---

### Task 4: Refresh REALITY Boundary Docs And Verification Notes

**Files:**
- Modify: `crates/xray-transport/src/reality_connector.rs`
- Modify: `docs/verification.md`

- [ ] **Step 1: Update connector documentation**

Replace the module documentation block at the top of `crates/xray-transport/src/reality_connector.rs` with:

```rust
//! REALITY connector boundary.
//!
//! Oracle/source: `Xray-core/transport/internet/reality/reality.go::UClient`.
//!
//! The pure session-id sealing and ClientHello patching primitives live in
//! `crate::reality`. This connector remains non-networked until the project has a
//! Chrome/uTLS-compatible ClientHello generator and REALITY certificate
//! verification.
//!
//! Future `RealityConnector::connect` implementation notes:
//!
//! 1. Build a Chrome-compatible TLS 1.3 ClientHello and expose its raw bytes,
//!    random, session-id offset, and ECDHE key share.
//! 2. Compute the X25519 shared secret with the configured REALITY server public
//!    key.
//! 3. Call `seal_reality_client_hello` to zero, seal, and patch the ClientHello
//!    session id.
//! 4. Complete the TLS handshake with the patched ClientHello.
//! 5. Verify the REALITY certificate HMAC.
//!
//! This logic stays inside `xray-transport`; VLESS should only see an async byte
//! stream once live REALITY networking is implemented.
```

- [ ] **Step 2: Update verification docs**

Add this section to `docs/verification.md` after the "Local Rust Checks" section:

````markdown
## REALITY Primitive Oracle

The REALITY session-id primitive is checked against committed fixtures generated by a small Go standard-library helper:

```sh
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
cargo test -p xray-transport reality_tests
```

These checks validate the deterministic Xray-core-compatible session-id sealing and ClientHello patching primitive. They do not prove a live REALITY connector, Chrome/uTLS ClientHello synthesis, certificate HMAC verification, or Vision flow yet.
````

- [ ] **Step 3: Run connector and docs-adjacent tests**

Run:

```bash
cargo test -p xray-transport reality_connector_tests
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

Expected: both commands PASS.

- [ ] **Step 4: Commit docs refresh**

Run:

```bash
git add crates/xray-transport/src/reality_connector.rs docs/verification.md
git commit -m "docs(transport): clarify reality primitive boundary"
```

---

### Task 5: Full Verification

**Files:**
- Verify the whole workspace.

- [ ] **Step 1: Check formatting**

Run:

```bash
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 2: Run clippy**

Run:

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: PASS.

- [ ] **Step 3: Run full Rust tests**

Run:

```bash
cargo test --workspace --all-targets
```

Expected: PASS. In this sandbox, tests that bind/connect loopback need escalated permission.

- [ ] **Step 4: Run REALITY oracle check**

Run:

```bash
go run ./tools/reality-oracle/session_id_vectors.go --check tests/fixtures/reality/session_id_vectors.json
```

Expected: PASS with no output.

- [ ] **Step 5: Check git status**

Run:

```bash
git status --short
```

Expected: no output.

If formatting changed files in Step 1 after a non-check format run, commit the formatting-only changes with:

```bash
git add Cargo.toml crates/xray-transport/Cargo.toml crates/xray-transport/src/reality.rs crates/xray-transport/tests/reality_tests.rs crates/xray-transport/src/reality_connector.rs docs/verification.md tools/reality-oracle/session_id_vectors.go tests/fixtures/reality/session_id_vectors.json
git commit -m "style: format reality oracle foundation"
```
