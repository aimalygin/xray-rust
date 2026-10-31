# Quinn 0.11.9: bounded transmit quantum and receive batch

Canonical archive: https://static.crates.io/crates/quinn/quinn-0.11.9.crate

SHA256: `b9e20a958963c291dc322d98411f541009df2ced7b5a4f2bd52337638cfccf20`. Upstream licenses and complete source are retained.

The connection driver yields after its datagram counter reaches 64 instead of 20.
A final GSO group may exceed that threshold by up to nine datagrams.
The quantum remains finite; socket backpressure and the congestion controller
still bound sends. This reduces connection-lock and task scheduling handoffs.
`Connection::set_stream_receive_window` forwards to quinn-proto's setter of the
same name, which grows the window every receive stream offers.

`AsyncUdpSocket::max_receive_batch` lets a socket ask its endpoint for fewer
receive slots than quinn-udp's `BATCH_SIZE`, 32 on Linux and Android. The
endpoint sizes its receive buffer for that many datagrams, clamped to
`1..=BATCH_SIZE`, and offers the socket only those slots; the default keeps
upstream's batch. With GRO each slot holds 64 segments, so the upstream buffer
takes 2.9 MiB per endpoint, and XHTTP H3 opens an endpoint for every
connection.

All other source is unchanged. Apply XRAY-PATCH.diff with zero fuzz.
