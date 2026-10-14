package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var mu sync.Mutex

func logrow(x map[string]any) {
	x["time"] = float64(time.Now().UnixNano()) / 1e9
	mu.Lock()
	defer mu.Unlock()
	json.NewEncoder(os.Stdout).Encode(x)
}
func socks(port int, command byte, dest int) (net.Conn, int, error) {
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if e != nil {
		return nil, 0, e
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fail := func(e error) (net.Conn, int, error) { c.Close(); return nil, 0, e }
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return fail(e)
	}
	h := make([]byte, 2)
	if _, e = io.ReadFull(c, h); e != nil {
		return fail(e)
	}
	if h[1] != 0 {
		return fail(fmt.Errorf("socks auth"))
	}
	req := []byte{5, command, 0, 1, 198, 51, 100, 1, byte(dest >> 8), byte(dest)}
	if command == 3 {
		req = []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	}
	if _, e = c.Write(req); e != nil {
		return fail(e)
	}
	h = make([]byte, 4)
	if _, e = io.ReadFull(c, h); e != nil {
		return fail(e)
	}
	if h[1] != 0 {
		return fail(fmt.Errorf("socks reply %d", h[1]))
	}
	n := 4
	if h[3] == 4 {
		n = 16
	} else if h[3] != 1 {
		return fail(fmt.Errorf("unsupported socks address"))
	}
	h = make([]byte, n+2)
	if _, e = io.ReadFull(c, h); e != nil {
		return fail(e)
	}
	return c, int(h[n])<<8 | int(h[n+1]), nil
}
func udp(port, dest int) error {
	c, relay, e := socks(port, 3, 0)
	if e != nil {
		return e
	}
	defer c.Close()
	s, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return e
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(5 * time.Second))
	nonce := make([]byte, 16)
	rand.Read(nonce)
	q := []byte{nonce[0], nonce[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 37}
	q = append(q, []byte("xray-"+hex.EncodeToString(nonce))...)
	q = append(q, []byte("\x07example\x03com\x00\x00\x01\x00\x01")...)
	h := sha256.Sum256(q)
	tag := hex.EncodeToString(h[:8])
	logrow(map[string]any{"event": "udp-send", "tag": tag, "relayPort": relay, "localPort": s.LocalAddr().(*net.UDPAddr).Port})
	defer logrow(map[string]any{"event": "udp-finished", "tag": tag, "relayPort": relay})
	wire := []byte{0, 0, 0, 1, 198, 51, 100, 1, byte(dest >> 8), byte(dest)}
	wire = append(wire, q...)
	_, e = s.WriteToUDP(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay})
	if e != nil {
		return e
	}
	b := make([]byte, 4096)
	n, _, e := s.ReadFromUDP(b)
	if e != nil {
		logrow(map[string]any{"event": "udp-failure", "tag": tag, "relayPort": relay, "localPort": s.LocalAddr().(*net.UDPAddr).Port, "error": e.Error()})
		return e
	}
	if n < 10 || b[3] != 1 {
		return fmt.Errorf("bad socks UDP response")
	}
	b = b[10:n]
	expected := append([]byte(nil), q...)
	copy(expected[2:12], []byte{0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0})
	expected = append(expected, []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 1}...)
	if string(b) != string(expected) {
		return fmt.Errorf("nonce mismatch %s", tag)
	}
	return nil
}
func http(port, dest int) error {
	c, _, e := socks(port, 1, dest)
	if e != nil {
		return e
	}
	defer c.Close()
	_, e = fmt.Fprintf(c, "GET /v08-probe HTTP/1.1\r\nHost: synthetic.test\r\nConnection: close\r\n\r\n")
	if e != nil {
		return e
	}
	h := make([]byte, 12)
	if _, e = io.ReadFull(c, h); e != nil {
		return e
	}
	if string(h) != "HTTP/1.1 204" {
		return fmt.Errorf("HTTP status %q", h)
	}
	return nil
}
func main() {
	if len(os.Args) != 4 {
		panic("usage: probe socksPort tcpPort udpPort")
	}
	ports := make([]int, 3)
	for i := range ports {
		ports[i], _ = strconv.Atoi(os.Args[i+1])
	}
	for round := 0; round < 4; round++ {
		start := time.Now()
		jobs := make(chan string, 720)
		for i := 0; i < 240; i++ {
			jobs <- "http"
		}
		for i := 0; i < 480; i++ {
			jobs <- "udp"
		}
		close(jobs)
		counts := map[string]int{}
		var lock sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for kind := range jobs {
					var e error
					if kind == "http" {
						e = http(ports[0], ports[1])
					} else {
						e = udp(ports[0], ports[2])
					}
					key := kind + "Passed"
					if e != nil {
						key = kind + "Failed"
						logrow(map[string]any{"event": "failure", "kind": kind, "error": e.Error()})
					}
					lock.Lock()
					counts[key]++
					lock.Unlock()
				}
			}()
		}
		wg.Wait()
		logrow(map[string]any{"event": "round", "round": round, "counts": counts, "durationSeconds": time.Since(start).Seconds()})
		if round < 3 {
			time.Sleep(20 * time.Second)
		}
	}
}
