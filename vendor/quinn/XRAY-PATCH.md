# Quinn 0.11.9: bounded transmit quantum

Canonical archive: https://static.crates.io/crates/quinn/quinn-0.11.9.crate

SHA256: `b9e20a958963c291dc322d98411f541009df2ced7b5a4f2bd52337638cfccf20`. Upstream licenses and complete source are retained.

The connection driver yields after its datagram counter reaches 64 instead of 20.
A final GSO group may exceed that threshold by up to nine datagrams.
The quantum remains finite; socket backpressure and the congestion controller
still bound sends. This reduces connection-lock and task scheduling handoffs.
All other source is unchanged. Apply XRAY-PATCH.diff with zero fuzz.
