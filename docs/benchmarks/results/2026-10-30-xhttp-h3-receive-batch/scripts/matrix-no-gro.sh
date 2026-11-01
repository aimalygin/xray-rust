#!/bin/sh
# matrix2.sh <rounds> <outfile>: small receive batches when GRO does not coalesce
# (UDP_GRO off, one packet per datagram), the worst case for a small batch.
rounds=$1; outfile=$2
variants="g32 g8 g4 g2 g1"
scenarios="download:32 full-duplex:32 download:1"
r=1
while [ $r -le $rounds ]; do
  for sc in $scenarios; do
    traffic=${sc%:*}; flows=${sc#*:}
    order=$(echo $variants | tr ' ' '\n' | awk -v r=$r 'BEGIN{n=0}{a[n++]=$0}END{for(i=0;i<n;i++)print a[(i+r)%n]}')
    for v in $order; do
      b=${v#g}
      line=$(/run-one.sh "n-r$r-$v" "$traffic" "$flows" XRAY_EXP_NO_GRO=1 XRAY_EXP_RECV_BATCH=$b)
      echo "{\"round\": $r, \"variant\": \"nogro-b$b\", \"result\": $line}" >> "$outfile"
    done
  done
  r=$((r+1))
done
echo DONE >> "$outfile.done"
