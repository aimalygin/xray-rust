//go:build reality_oracle_masquerade_headers

// This oracle is intentionally invoked from the repository root with:
//
//	go run -C tools/reality-oracle/masquerade -tags reality_oracle_masquerade_headers . \
//	  -variant ws > tests/fixtures/masquerade/headers_chrome_ws.json
//
// `-C` moves Go, not the shell, so the redirect above is still relative to the
// repository root while `-check` takes a path relative to this directory:
//
//	go run -C tools/reality-oracle/masquerade -tags reality_oracle_masquerade_headers . \
//	  -variant ws -check ../../../tests/fixtures/masquerade/headers_chrome_ws.json
//
// It lives in a module of its own rather than in the root one, because pulling
// xray-core into the root module raises golang.org/x/crypto to a version that
// changes the ClientHello bytes uTLS emits, which breaks the committed REALITY
// fixtures. See the comment in this directory's go.mod before moving it.
//
// It emits the browser-masquerade header block Xray injects into every ws,
// httpupgrade, XHTTP and REALITY-probe request, straight out of the reference
// implementation (`common/utils.TryDefaultHeadersWith`). The Rust port in
// `crates/xray-transport/src/stream/masquerade.rs` is asserted against the
// committed fixtures rather than against a reading of `browser.go`, because
// the literals that matter -- the GREASEd `Sec-CH-UA` brand list, the exact
// non-canonical key casing, the User-Agent templates -- are easy to transcribe
// slightly wrong and impossible to notice afterwards.
//
// Unlike the ClientHello oracle, this output is NOT constant. Xray derives
// every browser version from the current date, offset by a draw from a PRNG
// seeded with the host CPU's identity (`utils.GetRandomizer`), so the version
// numbers move with the calendar and differ between machines. That is why the
// fixture carries a `versions` block: the Rust test feeds those numbers back in
// and then asserts every header byte-for-byte, which keeps the assertion exact
// without pinning our own version derivation to one machine on one day.
//
// `-check` therefore fails whenever the date or the host has moved the version
// numbers on. That is a regeneration prompt, not a regression.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/utils"
)

type headerEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// browserVersions records the version numbers this run of the oracle happened
// to anchor on, so a reader can tell a version drift apart from a real change
// and so the Rust test can reproduce the block exactly.
type browserVersions struct {
	Chrome  int    `json:"chrome"`
	Firefox int    `json:"firefox"`
	Safari  string `json:"safari"`
	Curl    string `json:"curl"`
}

type shape struct {
	Variant   string          `json:"variant"`
	UserAgent string          `json:"user_agent"`
	Versions  browserVersions `json:"versions"`
	Headers   []headerEntry   `json:"headers"`
}

// anchoredVersions reads the versions off the package-level user agent strings
// rather than calling SafariVersion()/CurlVersion() again: those functions draw
// from the global PRNG on every call, so a second call would report a different
// version than the one baked into the headers this oracle just emitted.
func anchoredVersions() (browserVersions, error) {
	firefox, err := strconv.Atoi(utils.AnchoredFirefoxVersion)
	if err != nil {
		return browserVersions{}, fmt.Errorf("parse Firefox version %q: %w", utils.AnchoredFirefoxVersion, err)
	}

	_, safariTail, found := strings.Cut(utils.SafariUA, "Version/")
	if !found {
		return browserVersions{}, fmt.Errorf("no Version/ in Safari UA %q", utils.SafariUA)
	}
	safari, _, found := strings.Cut(safariTail, " Safari/")
	if !found {
		return browserVersions{}, fmt.Errorf("no Safari/ in Safari UA %q", utils.SafariUA)
	}

	curl, found := strings.CutPrefix(utils.CurlUA, "curl/")
	if !found {
		return browserVersions{}, fmt.Errorf("no curl/ prefix in curl UA %q", utils.CurlUA)
	}

	return browserVersions{
		Chrome:  utils.AnchoredChromeVersion,
		Firefox: firefox,
		Safari:  safari,
		Curl:    curl,
	}, nil
}

func buildShape(variant string, userAgent string) (shape, error) {
	header := http.Header{}
	if userAgent != "" {
		header.Set("User-Agent", userAgent)
	}
	utils.TryDefaultHeadersWith(header, variant)

	entries := make([]headerEntry, 0, len(header))
	for key, values := range header {
		for _, value := range values {
			entries = append(entries, headerEntry{Key: key, Value: value})
		}
	}
	// Byte-wise on the literal key, which is the order Go's Request.Write uses
	// and the order the Rust serializer reproduces.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })

	versions, err := anchoredVersions()
	if err != nil {
		return shape{}, err
	}

	return shape{Variant: variant, UserAgent: userAgent, Versions: versions, Headers: entries}, nil
}

func main() {
	variant := flag.String("variant", "ws", "header variant: ws, fetch or nav")
	userAgent := flag.String("user-agent", "", "config User-Agent value; empty means none is set")
	checkPath := flag.String("check", "", "compare the generated block with a committed JSON file")
	flag.Parse()

	built, err := buildShape(*variant, *userAgent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build masquerade block: %v\n", err)
		os.Exit(1)
	}

	generated, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal masquerade block: %v\n", err)
		os.Exit(1)
	}
	generated = append(generated, '\n')

	if *checkPath == "" {
		_, _ = os.Stdout.Write(generated)
		return
	}

	expected, err := os.ReadFile(*checkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(expected, generated) {
		fmt.Fprintf(os.Stderr, "fixture mismatch: %s\n", *checkPath)
		os.Exit(1)
	}
}
