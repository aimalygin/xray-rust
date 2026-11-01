"""Median round trip of 20 UDP and 20 TCP pings over the container's
loopback, in ms, as JSON: shows what delayed.sh adds and that TCP is spared."""
import json, socket, statistics, sys, threading, time

def udp_rtts(n=20):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    def echo():
        for _ in range(n):
            data, peer = server.recvfrom(64)
            server.sendto(data, peer)
    threading.Thread(target=echo, daemon=True).start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtts = []
    for _ in range(n):
        start = time.perf_counter()
        client.sendto(b'x', server.getsockname())
        client.recvfrom(64)
        rtts.append((time.perf_counter() - start) * 1000)
    return rtts

def tcp_rtts(n=20):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    def echo():
        conn, _ = listener.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for _ in range(n):
            conn.sendall(conn.recv(64))
    threading.Thread(target=echo, daemon=True).start()
    client = socket.create_connection(listener.getsockname())
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    rtts = []
    for _ in range(n):
        start = time.perf_counter()
        client.sendall(b'x')
        client.recv(64)
        rtts.append((time.perf_counter() - start) * 1000)
    return rtts

print(json.dumps({'label': sys.argv[1] if len(sys.argv) > 1 else '',
                  'udp_rtt_ms': round(statistics.median(udp_rtts()), 3),
                  'tcp_rtt_ms': round(statistics.median(tcp_rtts()), 3)}))
