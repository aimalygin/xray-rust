#!/system/bin/sh
# usage: memtest.sh HOST_PID SERVER_PORT FLOWS PORT [DEST]
# N concurrent downloads through the VPN; samples host VmRSS every 0.25 s, reports VmHWM.
# Clients never half-close: each nc's stdin is header + a "sleep 987" that is killed once every
# flow has finished (Go Xray's downlinkOnly=1 s timer would otherwise kill flows idle >1 s after FIN).
hpid=$1; sport=$2; flows=$3; port=$4; dest=${5:-203.0.113.10}
M=/data/local/tmp/protob/m
hdr='GET / HTTP/1.1\r\nHost: bench.test\r\n\r\n'
cpu() { set -- $(cat /proc/$1/stat); echo $((${14}+${15})); }
mem() { grep -E "^$2:" /proc/$1/status | tr -s ' \t' ' ' | cut -d' ' -f2; }
hexport=$(printf '%04X' $sport)
conns() { cat /proc/net/tcp /proc/net/tcp6 | grep -c ":$hexport [0-9A-F]*:[0-9A-F]* 01 "; }
done_count() { ls $M | grep -c '^d'; }
rm -rf $M; mkdir -p $M
temp=$(dumpsys battery | grep -m1 ' temperature:' | tr -d ' ')
rss0=$(mem $hpid VmRSS); hwm0=$(mem $hpid VmHWM)
h0=$(cpu $hpid); t0=$(date +%s.%N)
i=0
while [ $i -lt $flows ]; do
  ( (printf "$hdr"; sleep 987) | timeout 300 nc $dest $port | (md5sum | sed "s/^/flow$i md5=/"; touch $M/d$i) ) &
  i=$((i+1))
done
rssmax=0; cmax=0; n=0
while [ $(done_count) -lt $flows ]; do
  r=$(mem $hpid VmRSS); [ "$r" -gt $rssmax ] && rssmax=$r
  n=$((n+1))
  if [ $((n % 4)) = 1 ]; then c=$(conns); [ $c -gt $cmax ] && cmax=$c; fi
  sleep 0.25
done
t1=$(date +%s.%N); h1=$(cpu $hpid)
pkill -f "sleep 987"
wait
sleep 2
echo "memresult flows=$flows rss0kb=$rss0 hwm0kb=$hwm0 rssmaxkb=$rssmax hwmkb=$(mem $hpid VmHWM) rssafterkb=$(mem $hpid VmRSS) srvconnsmax=$cmax ticks=$((h1-h0)) t0=$t0 t1=$t1 $temp"
