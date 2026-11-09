// A Google Drive stand-in for XDRIVE's live tests: Xray-core's own fakeDrive
// from drive_test.go, served on the paths of Google's real API (the token
// endpoint, drive/v3/files and upload/drive/v3/files) instead of the short
// ones its tests swap in, over TLS with HTTP/2 or HTTP/1.1 and over HTTP/3
// on the same port. Xray-core's server and this client reach it through
// streamSettings.address and port, so neither talks to Google.
//
// It runs inside the package, added without touching the checkout:
//
//	go -C <pinned checkout> test -c -overlay overlay.json \
//	    -o drive-server ./transport/internet/xdrive
//	XDRIVE_DRIVE_SERVER_DIR=<dir> drive-server -test.run TestXrayRustDriveServer
//
// where overlay.json maps transport/internet/xdrive/xray_rust_drive_server_test.go
// to this file. It writes <dir>/port, <dir>/pin (the certificate's SHA-256)
// and a line a request to <dir>/requests, and serves until killed.
package xdrive

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
)

type xrayRustStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *xrayRustStatusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func TestXrayRustDriveServer(t *testing.T) {
	dir := os.Getenv("XDRIVE_DRIVE_SERVER_DIR")
	if dir == "" {
		t.Skip("XDRIVE_DRIVE_SERVER_DIR is not set")
	}
	drive := &fakeDrive{
		files:      make(map[string]*fakeFile),
		failOnce:   make(map[string]bool),
		failStatus: make(map[string]int),
		failBody:   make(map[string]string),
		hosts:      make(map[string]bool),
	}
	log, err := os.Create(filepath.Join(dir, "requests"))
	if err != nil {
		t.Fatal(err)
	}
	var logMu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &xrayRustStatusRecorder{ResponseWriter: w, status: http.StatusOK}
		uri := r.URL.RequestURI()
		path := r.URL.Path
		switch {
		case path == "/token":
			drive.handleToken(rec, r)
		case path == "/upload/drive/v3/files":
			r.URL.Path = "/upload"
			drive.handleUpload(rec, r)
		case strings.HasPrefix(path, "/upload/drive/v3/files/"):
			r.URL.Path = "/upload/" + strings.TrimPrefix(path, "/upload/drive/v3/files/")
			drive.handleUpload(rec, r)
		case path == "/drive/v3/files":
			drive.handleFiles(rec, r)
		case strings.HasPrefix(path, "/drive/v3/files/"):
			r.URL.Path = "/files/" + strings.TrimPrefix(path, "/drive/v3/files/")
			drive.handleFile(rec, r)
		default:
			http.NotFound(rec, r)
		}
		logMu.Lock()
		fmt.Fprintln(log, "served", r.Proto, r.Method, r.Host, uri, rec.status)
		logMu.Unlock()
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1),
		DNSNames:  []string{"www.googleapis.com", "oauth2.googleapis.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pin := sha256.Sum256(der)

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	h2 := &http.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate},
		NextProtos: []string{"h2", "http/1.1"}}}
	go h2.ServeTLS(tcp, "", "")
	h3 := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate},
		NextProtos: []string{"h3"}}}
	go h3.Serve(udp)

	if err := os.WriteFile(filepath.Join(dir, "pin"), []byte(hex.EncodeToString(pin[:])), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "port"), []byte(strconv.Itoa(port)), 0o644); err != nil {
		t.Fatal(err)
	}
	select {}
}
