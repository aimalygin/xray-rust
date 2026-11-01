#!/bin/sh
# matrix.sh <rounds> <outfile>: interleaves receive-path variants across scenarios.
rounds=$1; outfile=$2
variants="b32 b8 b4 b2 b1 nogro"
scenarios="download:32 full-duplex:32 upload:32 download:1"
envfor() {
  case $1 in
    b32) echo "XRAY_EXP_NONE=1" ;;
    b8) echo "XRAY_EXP_RECV_BATCH=8" ;;
    b4) echo "XRAY_EXP_RECV_BATCH=4" ;;
    b2) echo "XRAY_EXP_RECV_BATCH=2" ;;
    b1) echo "XRAY_EXP_RECV_BATCH=1" ;;
    nogro) echo "XRAY_EXP_NO_GRO=1" ;;
  esac
}
r=1
while [ $r -le $rounds ]; do
  for sc in $scenarios; do
    traffic=${sc%:*}; flows=${sc#*:}
    # rotate variant order by round
    order=$(echo $variants | tr ' ' '\n' | awk -v r=$r 'BEGIN{n=0}{a[n++]=$0}END{for(i=0;i<n;i++)print a[(i+r)%n]}')
    for v in $order; do
      line=$(/run-one.sh "m-r$r-$v" "$traffic" "$flows" $(envfor $v))
      echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> "$outfile"
    done
  done
  r=$((r+1))
done
echo DONE >> "$outfile.done"
