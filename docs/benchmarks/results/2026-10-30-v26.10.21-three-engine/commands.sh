#!/bin/bash -p
set -euo pipefail

# Measurement replay record for the 2026-10-30 three-engine group. It assumes
# the frozen comparator assets at the absolute paths below and empty result
# directories, and refuses a different binary. run.sh and run2.sh beside the
# raw results ran the same commands with a quiet-machine wait before each one.
export LC_ALL=C
export TZ=UTC
unset CDPATH BASH_ENV ENV
ulimit -n 8192

candidate_root=/Users/antonmalygin/xray-rust
raw_root=/Users/antonmalygin/xray-rust/target/benchmarks/2026-10-30-three-engine
frozen=/Users/antonmalygin/xray-rust/target/benchmarks/2026-10-30-perf-final.noindex
xray_bench_binary=$frozen/bin/harness
xray_bench_sha256=e5a9561f140ef79d62802940d1c1fb0097b3155bb9c7cdf55acd7b52e6cba933
xray_rust_revision=123b9d8d95d3501103e9c8e8e93f8f245426fe31
xray_rust_binary=$frozen/bin/after
xray_rust_sha256=8ea36af1fc504ee5469e75dbaac87df80a4f90a47d31b56b07fc1cf4c76535ca
xray_core_version=v26.10.21
xray_core_revision=1b1647cd9ddf0abc34b981d4611fc03bcac1ca74
xray_core_binary=/private/tmp/xray-migration-tools/xray-v26.10.21
xray_core_sha256=b8c58f14180eb0cad5665fa2cefb7d10897eec945d007212a053fc1de2257ee8
sing_box_dir=$raw_root/comparators/sing-box
sing_box_tag=v1.14.4
sing_box_revision=c005f35300ce76427dc285481ec5695f5b179cd2
sing_box_build_tags=with_gvisor,with_utls,badlinkname,tfogo_checklinkname0
sing_box_binary=$raw_root/comparators/bin/sing-box-v1.14.4
sing_box_sha256=b163d69ea5a31bdffc40e2d49415330d383ca6399d6b19c1935eb7cb896577b5
geodata_dir=$raw_root/comparators/geodata
geoip_sha256=b71d1999439dde2de2d2b6844a2befa50c50211ff739785c005ca7c230a17d6a
geosite_sha256=d6787cf3d08b86402640e8c2a7a18c8d64b31944ffa5274d8a6e154c8f3ddc07

require_sha256() {
  test "$(/usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}')" = "$2"
}

test "$(/usr/bin/git -C "$sing_box_dir" rev-parse --verify HEAD)" = "$sing_box_revision"
test "$(/usr/bin/git -C "$sing_box_dir" describe --tags --exact-match)" = "$sing_box_tag"
require_sha256 "$xray_bench_binary" "$xray_bench_sha256"
require_sha256 "$xray_rust_binary" "$xray_rust_sha256"
require_sha256 "$xray_core_binary" "$xray_core_sha256"
require_sha256 "$sing_box_binary" "$sing_box_sha256"
require_sha256 "$geodata_dir/geoip.dat" "$geoip_sha256"
require_sha256 "$geodata_dir/geosite.dat" "$geosite_sha256"

# sing-box: go1.27.3, in $sing_box_dir:
#   go build -tags "$sing_box_build_tags" -o "$sing_box_binary" ./cmd/sing-box
# geodata: scripts/fetch-geodata.sh --output-dir "$geodata_dir"

base=(--xray-rust-bin "$xray_rust_binary" --xray-core-bin "$xray_core_binary" --no-auto-build)
sing=(--sing-box-bin "$sing_box_binary" --sing-box-dir "$sing_box_dir")
bench() { "$xray_bench_binary" "$@"; }

bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload idle --duration-ms 5000 \
  --out-dir "$raw_root/base-idle"
bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload many-idle-flows --connections 100 \
  --duration-ms 5000 --out-dir "$raw_root/base-flows-100"
# In one compare invocation Xray-core's third 1,000-flow run (after xray-rust's
# five) failed with a reset SOCKS handshake and 4,800 sockets in TIME_WAIT:
#   bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload many-idle-flows \
#     --connections 1000 --duration-ms 5000 --out-dir "$raw_root/base-flows-1000"
# The published 1,000-flow series run one engine at a time, 90 s apart. Every
# sing-box attempt (-sing-box, -2, -3) failed in its first run.
for engine in xray-rust xray-core sing-box; do
  sleep 90
  case "$engine" in
    sing-box) bins=("${sing[@]}") ;;
    *) bins=(--xray-rust-bin "$xray_rust_binary" --xray-core-bin "$xray_core_binary") ;;
  esac
  bench run --engine "$engine" "${bins[@]}" --no-auto-build --runs 5 --workload many-idle-flows \
    --connections 1000 --duration-ms 5000 --out-dir "$raw_root/base-flows-1000-$engine"
done
bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload tcp-freedom --connections 1 \
  --iterations 1000 --payload-size 1024 --out-dir "$raw_root/base-tcp"
bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload udp-freedom --connections 1 \
  --iterations 1000 --payload-size 512 --out-dir "$raw_root/base-udp"
bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload reconnect-burst --connections 16 \
  --iterations 25 --out-dir "$raw_root/base-reconnect"
bench compare "${base[@]}" --skip-sing-box --runs 5 --workload reality-vision-xudp \
  --connections 1 --iterations 1000 --payload-size 512 --out-dir "$raw_root/base-reality-xudp"
bench compare "${base[@]}" "${sing[@]}" --runs 5 --workload tcp-bulk-throughput --connections 1 \
  --iterations 2048 --payload-size 4194304 --run-timeout-ms 300000 --out-dir "$raw_root/base-tcp-bulk"
bench compare "${base[@]}" --skip-sing-box --runs 5 --workload reality-vision-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000 \
  --out-dir "$raw_root/base-reality-bulk"
bench compare "${base[@]}" --runs 5 --workload routed-tcp-freedom --geodata-dir "$geodata_dir" \
  --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000 \
  --out-dir "$raw_root/base-geodata"

# Diagnostic, not published: stable sing-box's REALITY client against the
# v26.10.21 server (the server sent it to the cover origin).
#   bench compare "${base[@]}" "${sing[@]}" --runs 1 --workload reality-vision-xudp \
#     --connections 1 --iterations 100 --payload-size 512 --run-timeout-ms 60000 \
#     --out-dir "$raw_root/probe-sing-box-reality"

for transport in ws httpupgrade grpc xhttp-h1 xhttp-h2 xhttp-h3; do
  for traffic in upload download full-duplex; do
    for flows in 1 32; do
      scenario="stream-$transport-$traffic-$flows"
      args=(compare --workload stream-transport --stream-transport "$transport" --traffic "$traffic")
      case "$transport" in
        xhttp-*) args+=(--xhttp-mode stream-up) ;;
      esac
      args+=(--connections "$flows" --iterations 4096 --payload-size 65536
             --runs 5 --run-timeout-ms 300000 --out-dir "$raw_root/$scenario" "${base[@]}")
      case "$transport" in
        ws|httpupgrade|grpc) args+=("${sing[@]}") ;;
      esac
      bench "${args[@]}"
    done
  done
done
# stream-ws-upload-1 and -32 again, into "$raw_root/$scenario-rerun": the
# repository changed during their first runs (a dirty workspace, then mixed
# provenance when a commit landed mid-scenario).

for transport in xhttp-h1 xhttp-h2 xhttp-h3; do
  for flows in 1 32; do
    bench compare --workload stream-transport --stream-transport "$transport" \
      --traffic packet-up --xhttp-mode packet-up --connections "$flows" --iterations 4096 \
      --payload-size 16384 --runs 5 --run-timeout-ms 300000 \
      --out-dir "$raw_root/xhttp-pressure-$transport-$flows" "${base[@]}"
  done
done

memory=(compare --workload stream-transport --xhttp-profile legacy-extra-h1-packet-up
        --sample-interval-ms 100 --settle-ms 5000 --runs 5)
for flows in 1 16 32; do
  bench "${memory[@]}" --xhttp-max-post-bytes 500000 --traffic held-open --connections "$flows" \
    --iterations 1 --payload-size 16384 --duration-ms 30000 --run-timeout-ms 155000 \
    --out-dir "$raw_root/xhttp-memory-held-open-$flows-max-500000" "${base[@]}"
done
bench "${memory[@]}" --xhttp-max-post-bytes 16384 --traffic held-open --connections 16 \
  --iterations 1 --payload-size 16384 --duration-ms 30000 --run-timeout-ms 155000 \
  --out-dir "$raw_root/xhttp-memory-held-open-16-control-16384" "${base[@]}"
for flows in 1 16; do
  bench "${memory[@]}" --xhttp-max-post-bytes 500000 --traffic packet-up --connections "$flows" \
    --iterations 1000 --payload-size 16384 --duration-ms 0 --run-timeout-ms 300000 \
    --out-dir "$raw_root/xhttp-memory-packet-up-$flows-max-500000" "${base[@]}"
done

# Charts, rendered by xray-bench from f99a2729 (adds --omit-sing-box-1000-flows)
# from the reviewed summaries copied to chart-inputs/.
publication="$candidate_root/docs/benchmarks/results/2026-10-30-v26.10.21-three-engine"
chart_args=()
for group in idle many-idle-flows-100 many-idle-flows-1000 tcp-freedom udp-freedom \
  reconnect-burst reality-vision-xudp tcp-bulk-throughput reality-vision-bulk-throughput \
  routed-tcp-freedom; do
  chart_args+=(--group "$publication/chart-inputs/$group")
done
"$candidate_root/target/release/xray-bench" chart "${chart_args[@]}" \
  --date 2026-10-30 \
  --hardware 'Apple M6 (Mac18,5, 12 cores, 32 GB), macOS 27.0' \
  --xray-rust-version 123b9d8 \
  --xray-core-version v26.10.21 \
  --sing-box-version v1.14.4 \
  --geodata-version 'geoip b71d1999439d; geosite d6787cf3d08b' \
  --omit-sing-box-reality --omit-sing-box-1000-flows \
  --out-dir "$publication/media"
