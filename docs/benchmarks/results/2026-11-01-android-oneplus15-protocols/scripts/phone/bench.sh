#!/system/bin/sh
# usage: bench.sh HOST_PID SERVER_PID SERVER_PORT MODE(idle|dl|ul) FLOWS BYTES_PER_FLOW PORT [DEST]
# Clients run as shell UID 2000; DEST (TEST-NET-3) is the only range routed into the VPN.
# The proxy server (Go Xray) redirects to 127.0.0.1:PORT on loopback, outside the VPN.
# Clients never half-close: stdin stays open until the reply is complete (marker file), because
# Mux.Cool has no half-close (client End closes the whole session) and Go freedom drops FIN.
hpid=$1; spid=$2; sport=$3; mode=$4; flows=$5; bytes=$6; port=$7; dest=${8:-203.0.113.10}
M=/data/local/tmp/protob/m
TMO=${TMO:-180}
hdr='GET / HTTP/1.1\r\nHost: bench.test\r\n\r\n'
cpu() { set -- $(cat /proc/$1/stat); echo $((${14}+${15})); }
mem() { grep -E "^$2:" /proc/$1/status | tr -s ' \t' ' ' | cut -d' ' -f2; }
hold() { while [ ! -e $M/d$1 ]; do sleep 0.05; done; }
hexport=$(printf '%04X' $sport)
conns() { cat /proc/net/tcp /proc/net/tcp6 | grep -c ":$hexport [0-9A-F]*:[0-9A-F]* 01 "; }
rm -rf $M; mkdir -p $M
temp=$(dumpsys battery | grep -m1 ' temperature:' | tr -d ' ')
h0=$(cpu $hpid); s0=$(cpu $spid); t0=$(date +%s.%N)
i=0
[ $mode = idle ] && { sleep $bytes; flows=0; }
while [ $i -lt $flows ]; do
  if [ $mode = dl ]; then
    ( (printf "$hdr"; hold $i) | timeout $TMO nc $dest $port | (md5sum | sed "s/^/flow$i md5=/"; touch $M/d$i) ) &
  else
    ( (printf "$hdr"; head -c $bytes /dev/zero; hold $i) | timeout $TMO nc $dest $port | (sed "s/^/flow$i srvcount=/"; touch $M/d$i) ) &
  fi
  i=$((i+1))
done
c=0
if [ $flows -gt 0 ]; then
  sleep 1; c=$(conns)
fi
wait
t1=$(date +%s.%N); h1=$(cpu $hpid); s1=$(cpu $spid)
echo "result mode=$mode flows=$flows bytes=$bytes ticks=$((h1-h0)) srvticks=$((s1-s0)) srvconns=$c hwmkb=$(mem $hpid VmHWM) rsskb=$(mem $hpid VmRSS) t0=$t0 t1=$t1 $temp"
