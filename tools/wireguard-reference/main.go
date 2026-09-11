// Test-only standalone official wireguard-go peer. No Xray imports, host TUN,
// route changes or production WireGuard code are used by this fixture.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type config struct {
	Listen       string `json:"listen"`
	PrivateKey   string `json:"privateKey"`
	PeerKey      string `json:"peerKey"`
	PresharedKey string `json:"presharedKey"`
	RedirectPort uint16 `json:"redirectPort"`
	PacketSocket string `json:"packetSocket"`
	PacketClient string `json:"packetClient"`
}

func readConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid reference config")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing reference config")
	}
	for _, key := range []string{c.PrivateKey, c.PeerKey, c.PresharedKey} {
		if key == "" && c.PresharedKey == key {
			continue
		}
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			return c, errors.New("invalid reference key")
		}
	}
	if len(c.PrivateKey) != 64 || len(c.PeerKey) != 64 {
		return c, errors.New("missing reference key")
	}
	address, err := netip.ParseAddrPort(c.Listen)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return c, errors.New("reference listener must be loopback with a nonzero port")
	}
	if (c.PacketSocket == "") != (c.PacketClient == "") {
		return c, errors.New("incomplete packet bridge")
	}
	return c, nil
}

func run(c config) error {
	address, _ := netip.ParseAddrPort(c.Listen)
	tun := newPacketTun()
	defer tun.Close()
	if c.PacketSocket == "" {
		closeStack, err := attachForwarder(tun, c.RedirectPort)
		if err != nil {
			return err
		}
		defer closeStack()
	} else {
		socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: c.PacketSocket, Net: "unixgram"})
		if err != nil {
			return err
		}
		defer socket.Close()
		defer os.Remove(c.PacketSocket)
		tun.writePacket = func(packet []byte) error {
			_ = socket.SetWriteDeadline(time.Now().Add(time.Second))
			_, err := socket.WriteToUnix(packet, &net.UnixAddr{Name: c.PacketClient, Net: "unixgram"})
			return err
		}
		go func() {
			packet := make([]byte, mtu+1)
			for {
				n, from, err := socket.ReadFromUnix(packet)
				if err != nil {
					return
				}
				if from.Name != c.PacketClient || n > mtu {
					continue
				}
				if !tun.inject(append([]byte(nil), packet[:n]...)) {
					return
				}
			}
		}()
	}
	// Only the injected I/O boundary is ours; authentication, replay, peer source
	// checks, rekeying and all packet cryptography remain in official wireguard-go.
	dev := device.NewDevice(tun, &loopbackBind{ip: address.Addr()}, device.NewLogger(device.LogLevelError, "reference: "))
	defer dev.Close()
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.44.0.2/32\nallowed_ip=fd44::2/128\n", c.PrivateKey, address.Port(), c.PeerKey)
	if c.PresharedKey != "" {
		uapi += "preshared_key=" + c.PresharedKey + "\n"
	}
	if err := dev.IpcSet(uapi); err != nil {
		return errors.New("reference device configuration failed")
	}
	if err := dev.Up(); err != nil {
		return errors.New("reference device startup failed")
	}
	fmt.Println("wireguard-go reference ready")
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	select {
	case <-stopped:
	case <-dev.Wait():
	}
	return nil
}

func main() {
	if len(os.Args) != 2 || strings.HasPrefix(os.Args[1], "-") {
		fmt.Fprintln(os.Stderr, "usage: wireguard-reference CONFIG.json")
		os.Exit(2)
	}
	c, err := readConfig(os.Args[1])
	if err == nil {
		err = run(c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
