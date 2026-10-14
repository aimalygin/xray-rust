package main

import (
	"crypto/rand"
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

func main() {
	if len(os.Args) != 3 {
		panic("endpoint count")
	}
	count, _ := strconv.Atoi(os.Args[2])
	if count < 1 || count > 20000 {
		panic("count")
	}
	jobs := make(chan int, count)
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	failed := 0
	started := time.Now()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				nonce := make([]byte, 16)
				rand.Read(nonce)
				tag := hex.EncodeToString(nonce)
				stage := "connect"
				begin := time.Now()
				c, e := net.DialTimeout("tcp", os.Args[1], 5*time.Second)
				local := ""
				if e == nil {
					local = c.LocalAddr().String()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					stage = "write"
					_, e = fmt.Fprintf(c, "GET /v08-probe HTTP/1.1\r\nHost: synthetic.test\r\nX-Probe-Nonce: %s\r\nConnection: close\r\n\r\n", tag)
					if e == nil {
						stage = "read"
						h := make([]byte, 12)
						_, e = io.ReadFull(c, h)
						if e == nil && string(h) != "HTTP/1.1 204" {
							e = fmt.Errorf("bad HTTP response")
						}
					}
					c.Close()
				}
				mu.Lock()
				if e == nil {
					passed++
				} else {
					failed++
					json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "failure", "sequence": seq, "nonce": tag, "stage": stage, "local": local, "error": e.Error(), "seconds": time.Since(begin).Seconds()})
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "summary", "attempts": count, "passed": passed, "failed": failed, "workers": 32, "deadlineSeconds": 5, "durationSeconds": time.Since(started).Seconds()})
}
