# BLAKE3 byte-context API

Source: published `blake3` 1.8.5 crate, upstream commit
`93a431c78a52d7ccf0f366f106467f5070e6075e`.
Archive SHA-256: `0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce`.
`scripts/check-vendored-sources.sh` downloads that canonical archive, applies
`XRAY-PATCH.diff` without fuzz, and requires an exact tree match.

The sole source change adds `Hasher::new_derive_key_bytes(&[u8])`, using the
same context hash and material flags as `new_derive_key(&str)`. This matches
the upstream C raw-context API and Go's byte-preserving string conversion.
VLESS uses binary IVs and key-exchange messages as contexts. Converting them
to UTF-8, hex, or base64 would change the wire keys; constructing an invalid
Rust `str` would be undefined behavior. No compression/tree primitive changes.

The workspace enables `pure` and `zeroize`. Protocol tests compare binary
contexts across BLAKE3 block/chunk boundaries against the pinned Go oracle,
as well as checking equality with the original string API for valid UTF-8.
Remove this patch when an upstream release exposes an equivalent byte API.
