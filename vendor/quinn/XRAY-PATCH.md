# Quinn 0.11.12: bounded transmit quantum, receive batch and the socket before a rebind

Canonical archive: https://static.crates.io/crates/quinn/quinn-0.11.12.crate

SHA256: `4051e23e9185c255a7e33ef59cdbca87a22d359052eecd22fc6b901fb37d9d11`. Upstream licenses and complete source are retained.

## Package

The copy is the package `xray-quinn` 0.11.1200: quinn 0.11.12, fork release 0
(`docs/vendored-forks.md`). The library is still named `quinn`.
`XRAY-PATCH.diff` carries that in the manifest, the lockfile and a notice
above upstream's README. The manifest changes the name, version, description
and `repository`, and excludes `Cargo.toml.orig` and `.cargo_vcs_info.json`:
both came with upstream's archive, and cargo writes its own into every
package. It names quinn-proto as the package `xray-quinn-proto`, by the path
`../quinn-proto` in this repository and by version when published; upstream's
manifest asks for quinn-proto 0.11.18, and this copy has always been built on
the vendored 0.11.19. The lockfile is the published one brought in line with
the manifest.

## Changes

Rebased from 0.11.9 with the vendored quinn-proto's move to 0.11.19; the
patch applied without conflicts. 0.11.12 also bounds `read_to_end` by the
cumulative size of what it reads, fixes the connection and endpoint handle
reference counts, and handles a timer whose deadline has passed without
polling it.

The connection driver yields after its datagram counter reaches 64 instead of 20.
A final GSO group may exceed that threshold by up to nine datagrams.
The quantum remains finite; socket backpressure and the congestion controller
still bound sends. This reduces connection-lock and task scheduling handoffs.
`Connection::set_stream_receive_window` forwards to quinn-proto's setter of the
same name, which sets the window every receive stream offers.

`AsyncUdpSocket::max_receive_batch` lets a socket ask its endpoint for fewer
receive slots than quinn-udp's `BATCH_SIZE`, 32 on Linux and Android. The
endpoint sizes its receive buffer for that many datagrams, clamped to
`1..=BATCH_SIZE`, and offers the socket only those slots; the default keeps
upstream's batch. With GRO each slot holds 64 segments, so the upstream buffer
takes 2.9 MiB per endpoint, and XHTTP H3 opens an endpoint for every
connection.

After `Endpoint::rebind`, the previous socket goes on receiving for three
seconds after the first packet on the new one, where upstream closes it on
that packet; and the endpoint driver comes back to it when the work limiter
ended its poll with datagrams left, where upstream ignored that and left the
socket without a wake-up. A peer's datagrams for the old path arrive after
its first one for the new path whenever the old path is the slower one:
upstream dropped those with the socket, and read what had arrived earlier
only at the next packet on the new socket. QUIC sends a DATAGRAM frame once,
so a tunnel over datagrams lost its packets of that moment.

## The rustls dependency

The `rustls` dependency is the crates.io package `shaped-rustls` (the
ClientHello-shaping fork of rustls 0.23.46, whose library is still named
`rustls`), version `0.23.4600`, where upstream's manifest names the `rustls`
package. The workspace builds its TLS and QUIC client
configurations on that fork's types, and it no longer puts the fork under the
name `rustls` with `[patch.crates-io]`. No source file changes for this.
The copy's lockfile names the fork release it was locked on, and
`scripts/check-vendored-sources.sh` moves it to the release the workspace
builds before the locked test, so the crate's own tests run on that one.

## No `platform-verifier` feature

`platform-verifier`, one of upstream's default features, builds a client
configuration with the rustls-platform-verifier crate, whose verifier and
builder extension are made for upstream's rustls. On `shaped-rustls` they are
types and traits of another crate, and the feature does not compile. It is
removed from this crate's features and from `xray-quinn-proto`, which held
the code. The workspace never enabled it: it builds its own
`rustls::ClientConfig` and hands it to quinn.

No source file of this crate changes for the two sections above. Apply
XRAY-PATCH.diff with zero fuzz.
