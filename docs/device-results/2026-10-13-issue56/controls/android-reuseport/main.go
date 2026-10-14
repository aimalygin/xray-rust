package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func listen(reuse bool) (net.PacketConn, error) {
	var lc net.ListenConfig
	if reuse {
		lc.Control = func(n, a string, c syscall.RawConn) error {
			var e error
			err := c.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1) })
			if err != nil {
				return err
			}
			return e
		}
	}
	return lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
}
func main() {
	rows := []map[string]any{}
	for _, reuse := range []bool{true, false} {
		sockets := []net.PacketConn{}
		ports := map[int]bool{}
		for i := 0; i < 32; i++ {
			s, e := listen(reuse)
			if e != nil {
				panic(e)
			}
			sockets = append(sockets, s)
			ports[s.LocalAddr().(*net.UDPAddr).Port] = true
		}
		started := time.Now()
		collisions := 0
		example := 0
		for i := 0; i < 10000; i++ {
			s, e := listen(reuse)
			if e != nil {
				panic(e)
			}
			port := s.LocalAddr().(*net.UDPAddr).Port
			if ports[port] {
				collisions++
				example = port
			}
			s.Close()
		}
		for _, s := range sockets {
			s.Close()
		}
		rows = append(rows, map[string]any{"reusePort": reuse, "heldListeners": 32, "allocations": 10000, "collisions": collisions, "examplePort": example, "seconds": time.Since(started).Seconds()})
	}
	json.NewEncoder(os.Stdout).Encode(rows)
	fmt.Fprintln(os.Stderr, "All temporary sockets closed")
}
