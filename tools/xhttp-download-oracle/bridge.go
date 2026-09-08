// Local TLS H1/H2/H3 frontends converging on one real Xray session namespace.
// Test-only: all listeners bind loopback and keys live only in this process.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"golang.org/x/net/http2"
)

func bridge(backend string) error {
	target, err := url.Parse("http://" + backend)
	if err != nil {
		return err
	}
	if target.Hostname() != "127.0.0.1" {
		return fmt.Errorf("backend must be loopback")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "download-oracle.test"}, DNSNames: []string{"download-oracle.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(cert)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}, NextProtos: []string{"h2", "http/1.1"}}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// Preserve streaming responses, including server-first VLESS data.
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)
		r.Header["X-Forwarded-For"] = nil
		for _, prefix := range []string{"/upload/", "/download/"} {
			if strings.HasPrefix(r.URL.Path, prefix) {
				r.URL.Path = "/split/" + strings.TrimPrefix(r.URL.Path, prefix)
			}
		}
	}
	proxy.FlushInterval = -1
	proxy.Transport = &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true, DisableKeepAlives: true, MaxIdleConnsPerHost: 32}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A streaming POST must not be drained before forwarding its response.
		// This matters for HTTP/1 server-first and long-lived stream-up requests.
		_ = http.NewResponseController(w).EnableFullDuplex()
		proxy.ServeHTTP(w, r)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, TLSConfig: tlsConfig}
	if err = http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer udp.Close()
	h3TLS := tlsConfig.Clone()
	h3TLS.NextProtos = []string{"h3"}
	quicListener, err := quic.ListenEarly(udp, h3TLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return err
	}
	defer quicListener.Close()
	h3Server := &http3.Server{Handler: handler, TLSConfig: h3TLS}
	defer h3Server.Shutdown(context.Background())
	failure := make(chan error, 2)
	go func() { failure <- server.Serve(tls.NewListener(listener, tlsConfig)) }()
	go func() { failure <- h3Server.ServeListener(quicListener) }()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"tcp": listener.Addr().String(), "h3": udp.LocalAddr().String(), "pin": hex.EncodeToString(hash[:])}); err != nil {
		return err
	}
	return <-failure
}
