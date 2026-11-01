#!/system/bin/sh
# Protocol bench, phone side (shell UID 2000): Go Xray server on 127.0.0.1:10001-10007
# plus loopback bulk servers it redirects to (freedom redirect 127.0.0.1:<same port>).
# Download servers first consume the 36-byte request so close() sends FIN, not RST.
# Upload servers read exactly header+N bytes and answer the count: Go Xray freedom does not
# propagate the client's half-close (no CloseWrite), so "wc -c until EOF" would never answer.
cd /data/local/tmp/protob
./xray run -c server.json > xray.log 2>&1 &
nc -L -s 127.0.0.1 -p 5401 sh -c 'head -c 36 >/dev/null; head -c 1073741824 /dev/zero' &
nc -L -s 127.0.0.1 -p 5402 sh -c 'head -c 36 >/dev/null; head -c 268435456 /dev/zero' &
nc -L -s 127.0.0.1 -p 5403 sh -c 'head -c 1073741860 | wc -c' &
nc -L -s 127.0.0.1 -p 5406 sh -c 'head -c 268435492 | wc -c' &
nc -L -s 127.0.0.1 -p 5407 sh -c 'head -c 16777252 | wc -c' &
nc -L -s 127.0.0.1 -p 5404 sh -c 'head -c 36 >/dev/null; head -c 16777216 /dev/zero' &
nc -L -s 127.0.0.1 -p 5405 sh -c 'head -c 36 >/dev/null; head -c 4194304 /dev/zero' &
echo "servers $$ started"
wait
