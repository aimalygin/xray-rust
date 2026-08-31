#!/bin/bash -p
set -euo pipefail

# Exact RC4 measurement replay record. It assumes the frozen comparator assets
# and measurement guard retained at the absolute paths below, and empty result
# output directories. It intentionally refuses a different checkout or binary.
export LC_ALL=C
export TZ=UTC
unset CDPATH BASH_ENV ENV
ulimit -n 8192

candidate_root=/Users/antonmalygin/xray-rust
candidate_revision=5b8dca35af08eddd42fdb648a1347ff896b0c59f
raw_root=/Users/antonmalygin/xray-rust/target/benchmarks/2026-08-29-v26.7.28
xray_bench_binary=/Users/antonmalygin/xray-rust/target/release/xray-bench
xray_bench_sha256=af267762984982eb819b03acf8df7d4f9b24db48c81e9ac45de4291aa10eb69f
xray_rust_binary=/Users/antonmalygin/xray-rust/target/release/xray-rust
xray_rust_sha256=207a1a6780f5d8221699e8b497bda9e5f85b0ca23ab1d829e2ae3359ef4269bd
xray_core_dir=/Users/antonmalygin/xray-rust/Xray-core
xray_core_version=v26.7.28
xray_core_revision=5ca6f4b7d4dc20a881d4330e498892697627ec0c
xray_core_binary=/Users/antonmalygin/xray-rust/target/bench-bin/xray-core-v26.7.28
xray_core_sha256=ea0f45cf68f70d2131de01acb30c08f039eb5f4c1935d8b4423be55bb8d4ee02
sing_box_dir=/Users/antonmalygin/xray-rust/target/benchmarks/2026-08-29-v26.7.28/comparators/sing-box
sing_box_tag=v1.13.20
sing_box_revision=56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778
sing_box_build_tags=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0
sing_box_binary=/Users/antonmalygin/xray-rust/target/benchmarks/2026-08-29-v26.7.28/comparators/bin/sing-box-v1.13.20
sing_box_sha256=553bcc06357999c70c6b06b54d7f8fffc96283cb9a75142ede58dc32a319d8f1
geodata_dir=/Users/antonmalygin/xray-rust/target/benchmarks/2026-08-29-v26.7.28/comparators/geodata
geoip_sha256=b71d1999439dde2de2d2b6844a2befa50c50211ff739785c005ca7c230a17d6a
geosite_sha256=d6787cf3d08b86402640e8c2a7a18c8d64b31944ffa5274d8a6e154c8f3ddc07
latest_release_response_sha256=4b03732baf34d90a2030dffc733ca67166038291150dd9de1e8fe81ab2087aca
latest_release_headers_sha256=d0e01bc66aa43662f98c1c49ee8318532b44e9234a8779b1fb07b301cc2261de
measurement_guard="$raw_root/measurement-guard.sh"
measurement_driver="$raw_root/run-measurement.sh"

require_sha256() {
  local path="$1"
  local expected="$2"
  test "$(/usr/bin/shasum -a 256 "$path" | /usr/bin/awk '{print $1}')" = "$expected"
}

test "$(/usr/bin/git -C "$candidate_root" rev-parse --verify HEAD)" = "$candidate_revision"
test "$(/usr/bin/git -C "$xray_core_dir" rev-parse --verify HEAD)" = "$xray_core_revision"
test "$(/usr/bin/git -C "$sing_box_dir" rev-parse --verify HEAD)" = "$sing_box_revision"
test "$(/usr/bin/git -C "$sing_box_dir" describe --tags --exact-match)" = "$sing_box_tag"
require_sha256 "$xray_bench_binary" "$xray_bench_sha256"
require_sha256 "$xray_rust_binary" "$xray_rust_sha256"
require_sha256 "$xray_core_binary" "$xray_core_sha256"
require_sha256 "$sing_box_binary" "$sing_box_sha256"
require_sha256 "$geodata_dir/geoip.dat" "$geoip_sha256"
require_sha256 "$geodata_dir/geosite.dat" "$geosite_sha256"
require_sha256 "$raw_root/sing-box-latest-release.json" "$latest_release_response_sha256"
require_sha256 "$raw_root/sing-box-latest-release.headers" "$latest_release_headers_sha256"

measure() {
  "$measurement_guard"
  "$measurement_driver" "$@"
}

base_common=(
  --xray-rust-bin "$xray_rust_binary"
  --xray-core-bin "$xray_core_binary"
  --xray-core-dir "$xray_core_dir"
)
sing_box_common=(
  --sing-box-bin "$sing_box_binary"
  --sing-box-dir "$sing_box_dir"
)

measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload idle --duration-ms 5000 \
  --out-dir "$raw_root/base-idle"
measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload many-idle-flows --connections 100 \
  --duration-ms 5000 --out-dir "$raw_root/base-flows-100"
measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload many-idle-flows --connections 1000 \
  --duration-ms 5000 --out-dir "$raw_root/base-flows-1000"
measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload tcp-freedom --connections 1 \
  --iterations 1000 --payload-size 1024 --out-dir "$raw_root/base-tcp"
measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload udp-freedom --connections 1 \
  --iterations 1000 --payload-size 512 --out-dir "$raw_root/base-udp"
measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload reconnect-burst --connections 16 \
  --iterations 25 --out-dir "$raw_root/base-reconnect"
measure "$xray_bench_binary" compare "${base_common[@]}" --skip-sing-box \
  --no-auto-build --runs 5 --workload reality-vision-xudp --connections 1 \
  --iterations 1000 --payload-size 512 --out-dir "$raw_root/base-reality-xudp"
measure "$xray_bench_binary" compare "${base_common[@]}" "${sing_box_common[@]}" \
  --no-auto-build --runs 5 --workload tcp-bulk-throughput --connections 1 \
  --iterations 2048 --payload-size 4194304 --run-timeout-ms 300000 \
  --out-dir "$raw_root/base-tcp-bulk"
measure "$xray_bench_binary" compare "${base_common[@]}" --skip-sing-box \
  --no-auto-build --runs 5 --workload reality-vision-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 \
  --run-timeout-ms 120000 --out-dir "$raw_root/base-reality-bulk"
measure "$xray_bench_binary" compare "${base_common[@]}" --no-auto-build --runs 5 \
  --workload routed-tcp-freedom --geodata-dir "$geodata_dir" --connections 8 \
  --iterations 100 --payload-size 1024 --run-timeout-ms 120000 \
  --out-dir "$raw_root/base-geodata"

for transport in ws httpupgrade grpc xhttp-h1 xhttp-h2 xhttp-h3; do
  for traffic in upload download full-duplex; do
    for flows in 1 32; do
      scenario="stream-$transport-$traffic-$flows"
      stream_args=(
        --workload stream-transport
        --stream-transport "$transport"
        --traffic "$traffic"
      )
      case "$transport" in
        xhttp-*) stream_args+=(--xhttp-mode stream-up) ;;
      esac
      stream_args+=(
        --connections "$flows" --iterations 4096 --payload-size 65536
        --runs 5 --run-timeout-ms 300000 --out-dir "$raw_root/$scenario"
        --xray-rust-bin "$xray_rust_binary"
        --xray-core-bin "$xray_core_binary"
        --xray-core-dir "$xray_core_dir"
        --no-auto-build
      )
      case "$transport:$traffic:$flows" in
        grpc:full-duplex:32)
          stream_args+=(--skip-sing-box)
          ;;
        ws:*|httpupgrade:*|grpc:*)
          stream_args+=(
            --sing-box-bin "$sing_box_binary"
            --sing-box-dir "$sing_box_dir"
          )
          ;;
      esac
      measure "$xray_bench_binary" compare "${stream_args[@]}"
    done
  done
done

for transport in xhttp-h1 xhttp-h2 xhttp-h3; do
  for flows in 1 32; do
    scenario="xhttp-pressure-$transport-$flows"
    pressure_args=(
      --workload stream-transport
      --stream-transport "$transport"
      --traffic packet-up --xhttp-mode packet-up
      --connections "$flows" --iterations 4096 --payload-size 16384
      --runs 5 --run-timeout-ms 300000 --out-dir "$raw_root/$scenario"
      --xray-rust-bin "$xray_rust_binary"
      --xray-core-bin "$xray_core_binary"
      --xray-core-dir "$xray_core_dir"
      --no-auto-build
    )
    if [[ "$transport:$flows" == xhttp-h3:32 ]]; then
      measure "$xray_bench_binary" run --engine xray-rust "${pressure_args[@]}"
    else
      measure "$xray_bench_binary" compare "${pressure_args[@]}"
    fi
  done
done

memory_common=(
  --workload stream-transport
  --xhttp-profile legacy-extra-h1-packet-up
  --sample-interval-ms 100 --settle-ms 5000 --runs 5
)
memory_tail=(
  --out-dir "$raw_root/xhttp-memory"
  --xray-rust-bin "$xray_rust_binary"
  --xray-core-bin "$xray_core_binary"
  --xray-core-dir "$xray_core_dir"
  --no-auto-build
)
for flows in 1 16 32; do
  measure "$xray_bench_binary" compare "${memory_common[@]}" \
    --xhttp-max-post-bytes 500000 --traffic held-open --connections "$flows" \
    --iterations 1 --payload-size 16384 --duration-ms 30000 \
    --run-timeout-ms 155000 "${memory_tail[@]}"
done
measure "$xray_bench_binary" compare "${memory_common[@]}" \
  --xhttp-max-post-bytes 16384 --traffic held-open --connections 16 \
  --iterations 1 --payload-size 16384 --duration-ms 30000 \
  --run-timeout-ms 155000 "${memory_tail[@]}"
for flows in 1 16; do
  measure "$xray_bench_binary" compare "${memory_common[@]}" \
    --xhttp-max-post-bytes 500000 --traffic packet-up --connections "$flows" \
    --iterations 1000 --payload-size 16384 --duration-ms 0 \
    --run-timeout-ms 300000 "${memory_tail[@]}"
done

# Render the seven light/dark base charts from the canonicalized summaries.
publication="$candidate_root/docs/benchmarks/results/2026-08-29-v26.7.28"
chart_args=()
for group in \
  idle many-idle-flows-100 many-idle-flows-1000 tcp-freedom udp-freedom \
  reconnect-burst reality-vision-xudp tcp-bulk-throughput \
  reality-vision-bulk-throughput routed-tcp-freedom; do
  chart_args+=(--group "$publication/chart-inputs/$group")
done
"$xray_bench_binary" chart "${chart_args[@]}" \
  --date 2026-08-29 \
  --hardware 'MacBook Pro (M3 Pro, 12 cores, 18 GB), macOS 26.5.2' \
  --xray-rust-version 'v0.4.1-rc.4 (5b8dca3)' \
  --xray-core-version v26.7.28 \
  --sing-box-version v1.13.20 \
  --geodata-version 'geoip b71d1999439d; geosite d6787cf3d08b' \
  --omit-sing-box-reality \
  --out-dir "$publication/media"
