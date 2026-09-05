// The oracle imports the exact pinned Xray implementation; it does not
// reimplement its handshake. All keys are generated for local synthetic tests.
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/proxy/vless/encryption"
	"lukechampine.com/blake3"
)

func main() {
	var err error
	if len(os.Args) == 2 && os.Args[1] == "vectors" {
		err = vectors()
	} else if len(os.Args) == 3 && os.Args[1] == "keypair" {
		err = keypair(os.Args[2])
	} else if len(os.Args) == 2 && os.Args[1] == "origin" {
		err = origin()
	} else if len(os.Args) == 6 && os.Args[1] == "serve" {
		err = serve(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	} else {
		err = fmt.Errorf("usage: oracle vectors | serve mode key-kind flip-offset application")
	}
	if err != nil {
		// Peer data, private keys, and raw upstream errors never enter logs.
		fmt.Fprintln(os.Stderr, "VLESS oracle operation failed")
		os.Exit(1)
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*197 + 131)
	}
	return b
}

func vectors() error {
	type vector struct {
		Context  string `json:"context"`
		Material string `json:"material"`
		Derived  string `json:"derived"`
		AES      string `json:"aes"`
		ChaCha   string `json:"chacha"`
	}
	result := struct {
		Upstream string   `json:"upstream"`
		Vectors  []vector `json:"vectors"`
		CTR      string   `json:"ctr"`
	}{Upstream: "5ca6f4b7d4dc20a881d4330e498892697627ec0c"}
	material := pattern(96)
	for _, n := range []int{0, 16, 63, 64, 65, 1023, 1024, 1025, 1120, 1216, 16645} {
		context := pattern(n)
		derived := make([]byte, 32)
		blake3.DeriveKey(derived, string(context), material)
		v := vector{Context: hex.EncodeToString(context), Material: hex.EncodeToString(material), Derived: hex.EncodeToString(derived)}
		header := []byte{23, 3, 3, 0, 47}
		v.AES = hex.EncodeToString(encryption.NewAEAD(context, material, true).Seal(nil, nil, pattern(31), header))
		v.ChaCha = hex.EncodeToString(encryption.NewAEAD(context, material, false).Seal(nil, nil, pattern(31), header))
		result.Vectors = append(result.Vectors, v)
	}
	masked := pattern(1088)
	encryption.NewCTR(material, pattern(16)).XORKeyStream(masked, masked)
	result.CTR = hex.EncodeToString(masked)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

type fragmentConn struct {
	net.Conn
	read    int
	written int
	flip    int
}

func (c *fragmentConn) Read(b []byte) (int, error) {
	if len(b) > 13 {
		b = b[:13]
	}
	n, err := c.Conn.Read(b)
	c.read += n
	return n, err
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	copyBytes := append([]byte(nil), b...)
	truncate := c.flip < -1 && c.written+len(b) > -c.flip-2
	if truncate {
		copyBytes = copyBytes[:max(0, -c.flip-2-c.written)]
		// Signal a deterministic EOF at the selected byte, then drain the
		// client's remaining hello. Closing with unread TCP data instead can
		// reset/discard the queued truncated reply on some kernels.
		defer func() {
			_ = c.Conn.(interface{ CloseWrite() error }).CloseWrite()
			_, _ = io.Copy(io.Discard, c.Conn)
			_ = c.Conn.Close()
		}()
	}
	if c.flip >= c.written && c.flip < c.written+len(b) {
		copyBytes[c.flip-c.written] ^= 1
	}
	n := 0
	for len(copyBytes) > 0 {
		length := min(17, len(copyBytes))
		written, err := c.Conn.Write(copyBytes[:length])
		n += written
		c.written += written
		copyBytes = copyBytes[written:]
		if err != nil {
			return n, err
		}
		if written == 0 {
			return n, io.ErrShortWrite
		}
	}
	if truncate {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func serve(mode, kind, flipText, application string) error {
	application, useTLS := strings.CutPrefix(application, "tls:")
	modes := map[string]uint32{"native": 0, "xorpub": 1, "random": 2}
	xorMode, ok := modes[mode]
	if !ok {
		return fmt.Errorf("mode")
	}
	flip, err := strconv.Atoi(flipText)
	if err != nil {
		return err
	}
	var privateKeys, publicKeys [][]byte
	for _, keyKind := range strings.Split(kind, "+") {
		private, public, err := generateKeypair(keyKind)
		if err != nil {
			return err
		}
		privateKeys = append(privateKeys, private)
		publicKeys = append(publicKeys, public)
	}
	scenario := application
	connections := 1
	rtt := "1rtt"
	padding := "100-35-35"
	clientPadding := ""
	seconds := int64(0)
	sessionScenario := scenario == "session" || strings.HasPrefix(scenario, "session-") ||
		scenario == "expire" || scenario == "cancel"
	if sessionScenario {
		connections = 2
		if scenario == "expire" || scenario == "cancel" {
			connections = 3
		}
		rtt = "0rtt"
		// Deterministic fragments exercise configured length and gap slots
		// without making the guarded test wait on wall-clock sleeps.
		padding = "100-35-35.100-0-0.100-35-35"
		clientPadding = padding + "."
		seconds = 120
		application = "echo"
		if strings.HasPrefix(scenario, "session-") {
			application = strings.TrimPrefix(scenario, "session-")
		}
	}
	server := new(encryption.ServerInstance)
	// Fixed legal server padding makes corruption offsets stable in the
	// single-connection cases and session fragmentation deterministic.
	if err := server.Init(privateKeys, xorMode, seconds, seconds, padding); err != nil {
		return err
	}
	defer server.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	var tlsConfig *tls.Config
	pin := ""
	if useTLS {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1),
			DNSNames:  []string{"encryption-oracle.test"},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(der)
		pin = hex.EncodeToString(digest[:])
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	}
	encodedKeys := make([]string, 0, len(publicKeys))
	for _, public := range publicKeys {
		encodedKeys = append(encodedKeys, base64.RawURLEncoding.EncodeToString(public))
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"address":    listener.Addr().String(),
		"encryption": "mlkem768x25519plus." + mode + "." + rtt + "." + clientPadding + strings.Join(encodedKeys, "."),
		"tlsPin":     pin,
	}); err != nil {
		return err
	}
	for index := range connections {
		if scenario == "expire" && index == 1 {
			server.RWLock.Lock()
			server.Sessions = make(map[[16]byte]*encryption.ServerSession)
			server.RWLock.Unlock()
		}
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		if useTLS {
			protected := tls.Server(conn, tlsConfig)
			if err := protected.Handshake(); err != nil {
				conn.Close()
				return err
			}
			conn = protected
		}
		observed := &fragmentConn{Conn: conn, flip: flip}
		expectResume := (scenario == "session" || strings.HasPrefix(scenario, "session-")) && index == 1
		expectFailure := (scenario == "expire" || scenario == "cancel") && index == 1
		err = serveConnection(server, observed, application, expectResume)
		conn.Close()
		if expectFailure && err != nil {
			continue
		}
		if err != nil {
			return err
		}
		if expectFailure {
			return fmt.Errorf("expected failed session")
		}
	}
	return nil
}

func serveConnection(server *encryption.ServerInstance, conn *fragmentConn, application string, expectResume bool) error {
	stream, err := server.Handshake(conn, nil)
	if err != nil {
		return err
	}
	resumeBytes := 16 + server.RelaysLength + 18 + 32
	if (conn.read == resumeBytes) != expectResume {
		return fmt.Errorf("unexpected handshake path")
	}
	if application == "vless" || application == "udp" || application == "xudp" {
		// Verify encryption is below the existing VLESS header/framing. The
		// integration client uses a fixed synthetic domain destination.
		header := make([]byte, 19)
		if _, err := io.ReadFull(stream, header); err != nil {
			return err
		}
		command := map[string]byte{"vless": 1, "udp": 2, "xudp": 3}[application]
		if header[0] != 0 || header[17] != 0 || header[18] != command {
			return fmt.Errorf("VLESS header")
		}
		if command != 3 {
			address := make([]byte, 3)
			if _, err := io.ReadFull(stream, address); err != nil {
				return err
			}
			if address[2] != 2 {
				return fmt.Errorf("VLESS address kind")
			}
			length := []byte{0}
			if _, err := io.ReadFull(stream, length); err != nil {
				return err
			}
			domain := make([]byte, int(length[0]))
			if _, err := io.ReadFull(stream, domain); err != nil {
				return err
			}
			if string(domain) != "encrypted.example.test" {
				return fmt.Errorf("VLESS destination")
			}
		}
		if _, err := stream.Write([]byte{0, 0}); err != nil {
			return err
		}
	} else if application != "echo" {
		return fmt.Errorf("application")
	}
	_, err = io.Copy(stream, stream)
	return err
}

func generateKeypair(kind string) (private, public []byte, err error) {
	if kind == "x25519" {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Bytes(), key.PublicKey().Bytes(), nil
	}
	if kind == "mlkem768" {
		key, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, nil, err
		}
		return key.Bytes(), key.EncapsulationKey().Bytes(), nil
	}
	return nil, nil, fmt.Errorf("key kind")
}

// Ephemeral test keys are sent only over the parent's private stdout pipe.
func keypair(kind string) error {
	private, public, err := generateKeypair(kind)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"private": base64.RawURLEncoding.EncodeToString(private), "public": base64.RawURLEncoding.EncodeToString(public)})
}

// A local TLS 1.3/H2 cover origin supporting X25519MLKEM768. REALITY detector
// probes never need the public Internet. Parent owns/kills this child directly.
func origin() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"encryption-oracle.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"address": listener.Addr().String()}); err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			io.Copy(io.Discard, conn)
		}()
	}
}
