# Scale and Geo-Rules Benchmarks Design

## Goal

Extend the published benchmark story with two dimensions that mirror real
client use: connection scale (1000 held flows) and routing with real
`geosite.dat`/`geoip.dat` exclusion rules. Publish two new README charts
(routing setup latency, routing memory) and a third group on the existing
memory chart, all reproducible through the existing `compare` → `chart`
pipeline.

## Scope

This slice delivers:

- workload parameters (`connections`, `iterations`, `payload_size`) persisted
  in `result.json`/`summary.json`;
- chart support for selecting summaries by workload parameters, enabling the
  same workload to appear at two scales;
- a `many-idle-flows` 1000-connection publication series charted as a third
  group on the memory chart;
- a new `routed-tcp-freedom` workload: SOCKS5 domain CONNECT through a config
  with real geosite/geoip routing rules, xray-rust vs Xray-core;
- two new charts (`geo-setup-latency`, `geo-memory`) and README updates.

Out of scope: sing-box in the geo workload (sing-box ≥1.8 does not read
Xray-format `.dat`; semantically equivalent `.srs` rule-sets cannot be
guaranteed — excluded honestly, like the TUN workloads), rule-set
microbenchmarks beyond one realistic config, DNS-over-network in benches,
time-to-ready startup metric.

## Workload Parameter Persistence

`BenchResult` and `BenchSummary` gain integer fields `connections`,
`iterations`, and `payload_size`, copied from `BenchOptions` at result
assembly. All additive with `#[serde(default)]`; older JSON deserializes with
zeros. `summarize_results` requires them uniform across runs (mixed values →
error, like mixed engines today).

## Chart Selection by Parameters

`load_summary` gains an optional `connections` filter: when several groups
contain the same engine/workload pair, a summary matching the requested
connection count is selected; ambiguity (two matches) stays an error. The
memory chart requests `many-idle-flows` twice — `connections: 100` and
`connections: 1000` — with group labels `many-idle-flows ×100` and
`many-idle-flows ×1000`. Old summaries without params (zeros) match only when
no filter is requested, so pre-change run groups keep working for the other
charts.

## 1000-Flow Series

No new workload: the publication recipe adds
`compare --workload many-idle-flows --connections 1000 --duration-ms 5000`.
Documented facts: xray-rust's inbound admission cap is 1024 connections
(`DEFAULT_MAX_INBOUND_CONNECTIONS`) — historical: the cap was removed later
the same day, see `specs/2026-07-30-remove-inbound-connection-cap.md` — so
1000 fits with little headroom and
higher counts would be refused — noted in docs/benchmarks.md; harness fd
usage (~3000) requires a raised `ulimit -n`, also noted. Probe measurement on
Apple M3 Pro: xray-rust holds 1000 flows at 12.1 MiB peak RSS, status ok.

## Geo-Rules Workload: `routed-tcp-freedom`

Topology is `tcp-freedom` (local echo server, SOCKS client, validated echo
payloads, per-iteration latency) with three changes:

1. **Domain CONNECT.** The harness SOCKS client learns ATYP=3 (domain)
   CONNECT alongside the existing IPv4 path. Each connection targets a domain
   name; the engine performs rule evaluation on the domain, resolves it via
   config `hosts`, and dials the local echo server.
2. **Real rules, hosts-pinned resolution.** Generated configs (xray-rust and
   Xray-core — identical JSON) carry a realistic rule list referencing real
   geodata categories, e.g. `geosite:category-ads-all`, `geosite:geolocation-!cn`,
   `geosite:cn`, `geoip:private`, `geoip:cn`, with several tagged `freedom`
   outbounds so every decision still routes traffic (nothing blackholed —
   echo validation must pass). Every `freedom` outbound sets
   `"domainStrategy": "UseIP"` so the engine resolves the domain through its
   own DNS/hosts layer — without this Xray-core would hand the raw domain to
   the OS resolver and the bench would touch real DNS. Two target domains per
   run: a **hit** domain that is a real member of a late-listed geosite
   category, and a **miss** domain (`bench-miss.invalid`) that falls through
   every rule to the default outbound. Both map to `127.0.0.1` via
   `dns.hosts`, so no packet leaves the machine. Connections alternate
   hit/miss 50/50; `connections`/`iterations` knobs as in tcp-freedom.
3. **Engine gating.** `supports_sing_box_process_engine` stays false for the
   workload; `compare` prints the standard skip message for sing-box.

Geodata files are an explicit input: `--geodata-dir <dir>` containing
`geosite.dat` and `geoip.dat`. The harness never downloads; a missing or
unreadable file is a clear error naming the flag. The publication recipe pins
an exact Xray geodata release tag and sha256 (fetched via
`scripts/fetch-geodata.sh` or curl), and the chart footer records the geodata
release alongside engine versions.

Headline metrics, both from existing collection machinery:

- `setup_socks_connect_us` (SOCKS CONNECT request→reply, which contains rule
  evaluation + hosts resolution + local dial) — chart `geo-setup-latency`,
  median with p95 whisker, one group over the 50/50 hit/miss mix (per-run
  setup samples are pooled into one summary, so hit and miss cannot be
  charted separately without splitting runs — the mix is the realistic
  aggregate and the p95 whisker exposes the slower path);
- `peak_rss_kib` with geodata loaded — chart `geo-memory`.

## Chart Module Changes

Charts gain a per-chart engine list (the geo charts render two bars:
xray-rust, Xray-core; existing charts keep three). Series colors stay bound
to engine identity (xray-rust blue, Xray-core orange) regardless of count.
Footer gains an optional `geodata` version segment, present only when the
chart set includes geo charts.

## README

Memory chart alt text and methodology sentence updated for the third group.
New section content: the two geo charts with a one-paragraph explanation of
what the rules config contains and why sing-box is absent from these two
charts. Alt texts carry the numbers as elsewhere.

## Testing

- Serde: old result.json/summary.json without params still deserialize;
  mixed-params summarize error.
- Chart selection: params filter picks the right summary; ambiguity and
  missing-params cases covered.
- Harness: domain-CONNECT SOCKS encoding unit test (byte-exact request);
  smoke test of `routed-tcp-freedom` against xray-rust with a synthetic tiny
  `.dat` fixture pair committed under `crates/xray-bench/testdata/geodata/`
  (a handful of domains/CIDRs, written by a test helper that encodes the
  protobuf format directly — the real multi-MB files are never committed).
- Golden charts regenerated; determinism/e2e tests extended for the new
  stems and 2-engine groups.

## Boundaries

All changes in `crates/xray-bench` except none — the production runtime is
untouched (rules, geosite/geoip, hosts, domain CONNECT are existing runtime
features; the bench only exercises them). Real geodata stays outside the
repository; only the tiny synthetic test fixture is committed.
