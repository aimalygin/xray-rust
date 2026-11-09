// A stand-in for the HTTP storages XDRIVE reaches, for its live tests. One
// store in memory served over HTTP and, with -cert and -key, over HTTPS with
// HTTP/2 as well, so that Xray-core's server and this client can meet in it
// over different transports. It prints {"http": "host:port", "https":
// "host:port"} once it listens and serves until killed.
//
// -mode s3 is one bucket, path-style or virtual-hosted: PUT, GET and DELETE
// of objects and ListObjectsV2 with prefix, delimiter and continuation, every
// request checked against AWS Signature Version 4 as the AWS documentation
// defines it, written apart from Xray-core's signer so that both clients are
// checked against the specification and not against each other.
//
// -mode template is a REST store for a "template" service: OAuth 2 tokens
// from a refresh token, or a static bearer token; PUT of a raw body or of
// JSON carrying it in base64; a GET that answers with a link to fetch, which
// redirects to the bytes; DELETE; and a flat listing. It refuses some
// requests on purpose, as services do: a 403 naming a rate limit, a 429, and
// tokens it forgets, so that both clients retry and refresh.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mode     = flag.String("mode", "s3", "s3 or template")
	listen   = flag.String("listen", "127.0.0.1:0", "address to serve HTTP on")
	tlsAddr  = flag.String("tls-listen", "127.0.0.1:0", "address to serve HTTPS on, with -cert and -key")
	certFile = flag.String("cert", "", "TLS certificate (PEM)")
	keyFile  = flag.String("key", "", "TLS key (PEM)")
	access   = flag.String("access", "", "s3: access key id")
	secret   = flag.String("secret", "", "s3: secret access key")
	token    = flag.String("token", "", "s3: session token, if any")
	region   = flag.String("region", "us-east-1", "s3: signing region")
	bucket   = flag.String("bucket", "", "s3: the one bucket")
	maxKeys  = flag.Int("page", 1000, "s3: most keys a listing page holds")
	refresh  = flag.String("refresh-token", "", "template: the refresh token a token request carries")
	clientID = flag.String("client-id", "", "template: the client id a token request carries")
	static   = flag.String("static-token", "", "template: a bearer token always accepted")
	lifetime = flag.Int("token-lifetime", 3600, "template: seconds a token is said to last")
)

type store struct {
	mu      sync.Mutex
	objects map[string][]byte
	// requests counts what was asked of each method, for the tests' logs
	requests map[string]int
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

// awsEscape is the URI encoding SigV4 asks for: unreserved characters kept,
// everything else %XX with uppercase hex, '/' kept where slashSafe.
func awsEscape(s string, slashSafe bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && slashSafe:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// verify checks r against SigV4 and returns the reason it fails, or "".
func verify(r *http.Request, body []byte) string {
	auth := r.Header.Get("Authorization")
	const algorithm = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, algorithm) {
		return "no SigV4 authorization"
	}
	fields := map[string]string{}
	for _, part := range strings.Split(auth[len(algorithm):], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "malformed authorization"
		}
		fields[k] = v
	}
	credential := strings.Split(fields["Credential"], "/")
	if len(credential) != 5 || credential[0] != *access || credential[2] != *region ||
		credential[3] != "s3" || credential[4] != "aws4_request" {
		return "credential scope " + fields["Credential"]
	}
	stamp := r.Header.Get("X-Amz-Date")
	at, err := time.Parse("20060102T150405Z", stamp)
	if err != nil || credential[1] != stamp[:8] {
		return "date " + stamp
	}
	if skew := time.Since(at); skew > 15*time.Minute || skew < -15*time.Minute {
		return "request time too skewed"
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	sum := sha256.Sum256(body)
	if payload != hex.EncodeToString(sum[:]) {
		return "payload hash"
	}
	if *token != "" && r.Header.Get("X-Amz-Security-Token") != *token {
		return "session token"
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(signed) {
		return "signed headers out of order"
	}
	required := map[string]bool{"host": false, "x-amz-date": false, "x-amz-content-sha256": false}
	if *token != "" {
		required["x-amz-security-token"] = false
	}
	var headers strings.Builder
	for _, name := range signed {
		if _, ok := required[name]; ok {
			required[name] = true
		}
		var value string
		if name == "host" {
			value = r.Host
		} else {
			values := r.Header.Values(name)
			if len(values) == 0 {
				return "signed header " + name + " missing"
			}
			for i, v := range values {
				values[i] = strings.Join(strings.Fields(v), " ")
			}
			value = strings.Join(values, ",")
		}
		headers.WriteString(name + ":" + value + "\n")
	}
	for name, seen := range required {
		if !seen {
			return "header " + name + " not signed"
		}
	}
	rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	// Re-encode the path as SigV4 does: decode each segment, escape it again.
	segments := strings.Split(rawPath, "/")
	for i, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return "path escape"
		}
		segments[i] = awsEscape(decoded, false)
	}
	canonicalPath := strings.Join(segments, "/")
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "query"
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pairs []string
	for _, k := range keys {
		values := append([]string(nil), query[k]...)
		sort.Strings(values)
		for _, v := range values {
			pairs = append(pairs, awsEscape(k, false)+"="+awsEscape(v, false))
		}
	}
	canonical := strings.Join([]string{r.Method, canonicalPath, strings.Join(pairs, "&"),
		headers.String(), fields["SignedHeaders"], payload}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	scope := strings.Join(credential[1:], "/")
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	key := hmacSHA256([]byte("AWS4"+*secret), credential[1])
	key = hmacSHA256(key, *region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	want := hex.EncodeToString(hmacSHA256(key, toSign))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return "signature"
	}
	return ""
}

type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	Xmlns                 string   `xml:"xmlns,attr"`
	Name                  string   `xml:"Name"`
	Prefix                string   `xml:"Prefix"`
	KeyCount              int      `xml:"KeyCount"`
	MaxKeys               int      `xml:"MaxKeys"`
	Delimiter             string   `xml:"Delimiter,omitempty"`
	IsTruncated           bool     `xml:"IsTruncated"`
	ContinuationToken     string   `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string   `xml:"NextContinuationToken,omitempty"`
	Contents              []struct {
		Key  string `xml:"Key"`
		Size int    `xml:"Size"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

func (s *store) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("list-type") != "2" {
		s3Error(w, http.StatusBadRequest, "InvalidRequest")
		return
	}
	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")
	limit := *maxKeys
	if v, err := strconv.Atoi(q.Get("max-keys")); err == nil && v < limit {
		limit = v
	}
	s.mu.Lock()
	keys := make([]string, 0, len(s.objects))
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sizes := map[string]int{}
	for _, k := range keys {
		sizes[k] = len(s.objects[k])
	}
	s.mu.Unlock()
	sort.Strings(keys)
	// One result per key or per common prefix, in order.
	type item struct {
		key    string
		common bool
	}
	var items []item
	seen := map[string]bool{}
	for _, k := range keys {
		if delimiter != "" {
			if cut := strings.Index(k[len(prefix):], delimiter); cut >= 0 {
				common := k[:len(prefix)+cut+len(delimiter)]
				if !seen[common] {
					seen[common] = true
					items = append(items, item{common, true})
				}
				continue
			}
		}
		items = append(items, item{k, false})
	}
	start := 0
	if token := q.Get("continuation-token"); token != "" {
		n, err := strconv.Atoi(token)
		if err != nil || n < 0 || n > len(items) {
			s3Error(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		start = n
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	result := listResult{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: *bucket, Prefix: prefix,
		MaxKeys: limit, Delimiter: delimiter, ContinuationToken: q.Get("continuation-token")}
	for _, it := range items[start:end] {
		if it.common {
			result.CommonPrefixes = append(result.CommonPrefixes, struct {
				Prefix string `xml:"Prefix"`
			}{it.key})
		} else {
			result.Contents = append(result.Contents, struct {
				Key  string `xml:"Key"`
				Size int    `xml:"Size"`
			}{it.key, sizes[it.key]})
		}
	}
	result.KeyCount = end - start
	if end < len(items) {
		result.IsTruncated = true
		result.NextContinuationToken = strconv.Itoa(end)
	}
	w.Header().Set("Content-Type", "application/xml")
	io.WriteString(w, xml.Header)
	xml.NewEncoder(w).Encode(result)
}

func (s *store) serveS3(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		s3Error(w, http.StatusBadRequest, "IncompleteBody")
		return
	}
	if reason := verify(r, body); reason != "" {
		fmt.Fprintln(os.Stderr, "refused", r.Method, r.RequestURI, ":", reason)
		s3Error(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return
	}
	s.mu.Lock()
	s.requests[r.Method]++
	s.mu.Unlock()
	// Path-style /bucket/key or virtual-hosted bucket.host/key.
	path := r.URL.Path
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	var key string
	if strings.HasPrefix(host, *bucket+".") {
		key = strings.TrimPrefix(path, "/")
	} else {
		rest, ok := strings.CutPrefix(path, "/"+*bucket)
		if !ok || (rest != "" && rest[0] != '/') {
			s3Error(w, http.StatusNotFound, "NoSuchBucket")
			return
		}
		key = strings.TrimPrefix(rest, "/")
	}
	switch {
	case key == "" && r.Method == http.MethodGet:
		s.list(w, r)
	case key == "":
		s3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	case r.Method == http.MethodPut:
		s.mu.Lock()
		s.objects[key] = bytes.Clone(body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet:
		s.mu.Lock()
		data, ok := s.objects[key]
		s.mu.Unlock()
		if !ok {
			s3Error(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	case r.Method == http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, key)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		s3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// templateStore is the "template" service: objects by folder and name.
type templateStore struct {
	mu       sync.Mutex
	objects  map[string][]byte
	links    map[string]string
	tokens   map[string]bool
	issued   int
	requests int
}

func jsonAnswer(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func randomID() string {
	var b [12]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func (s *templateStore) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
		jsonAnswer(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != *refresh ||
		r.PostForm.Get("client_id") != *clientID {
		fmt.Fprintln(os.Stderr, "refused a token request:", r.PostForm.Encode())
		jsonAnswer(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	s.mu.Lock()
	s.issued++
	issued := "tok-" + strconv.Itoa(s.issued) + "-" + randomID()
	s.tokens[issued] = true
	s.mu.Unlock()
	jsonAnswer(w, http.StatusOK, map[string]any{"access_token": issued, "token_type": "Bearer",
		"expires_in": *lifetime})
}

// api answers the storage requests, after the refusals that come at fixed
// counts: a forgotten token, a rate limit by reason and one by status.
func (s *templateStore) api(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		jsonAnswer(w, http.StatusBadRequest, map[string]string{"error": "body"})
		return
	}
	bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	s.requests++
	n := s.requests
	if n%47 == 0 {
		s.tokens = map[string]bool{}
	}
	known := s.tokens[bearer] || (*static != "" && bearer == *static)
	s.mu.Unlock()
	switch {
	case !known:
		jsonAnswer(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	case n%29 == 0:
		jsonAnswer(w, http.StatusForbidden, map[string]any{"error": map[string]string{"reason": "rateLimitExceeded"}})
		return
	case n%31 == 0:
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/")
	kind, name, _ := strings.Cut(rest, "/")
	switch {
	case kind == "list" && r.Method == http.MethodGet:
		folder := strings.TrimSuffix(name, "/") + "/"
		type entry struct {
			Name string `json:"name"`
		}
		entries := []entry{}
		s.mu.Lock()
		for key := range s.objects {
			if found, ok := strings.CutPrefix(key, folder); ok {
				entries = append(entries, entry{found})
			}
		}
		s.mu.Unlock()
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		jsonAnswer(w, http.StatusOK, map[string]any{"entries": entries})
	case kind != "files" || name == "":
		jsonAnswer(w, http.StatusNotFound, map[string]string{"error": "no such endpoint"})
	case r.Method == http.MethodPut:
		data := body
		if r.Header.Get("Content-Type") == "application/json" {
			var wrapped struct {
				Content string `json:"content"`
			}
			if err := json.Unmarshal(body, &wrapped); err != nil {
				jsonAnswer(w, http.StatusBadRequest, map[string]string{"error": "json"})
				return
			}
			if data, err = base64.StdEncoding.DecodeString(wrapped.Content); err != nil {
				jsonAnswer(w, http.StatusBadRequest, map[string]string{"error": "base64"})
				return
			}
		}
		s.mu.Lock()
		s.objects[name] = data
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet:
		s.mu.Lock()
		_, ok := s.objects[name]
		id := randomID()
		if ok {
			s.links[id] = name
		}
		s.mu.Unlock()
		if !ok {
			jsonAnswer(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		jsonAnswer(w, http.StatusOK, map[string]string{"href": scheme(r) + "://" + r.Host + "/link/" + id})
	case r.Method == http.MethodDelete:
		s.mu.Lock()
		_, ok := s.objects[name]
		delete(s.objects, name)
		for key := range s.objects {
			if strings.HasPrefix(key, name+"~") || strings.HasPrefix(key, name+"/") {
				delete(s.objects, key)
			}
		}
		s.mu.Unlock()
		if !ok {
			jsonAnswer(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		jsonAnswer(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
	}
}

// link redirects a fetched link to its bytes, as a download service hands a
// file to another host; raw answers it without auth.
func (s *templateStore) link(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/link/")
	http.Redirect(w, r, "/raw/"+url.PathEscape(id), http.StatusFound)
}

func (s *templateStore) raw(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/raw/")
	s.mu.Lock()
	name, ok := s.links[id]
	delete(s.links, id)
	data, found := s.objects[name]
	s.mu.Unlock()
	if !ok || !found {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *templateStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/oauth/token":
		s.token(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/"):
		s.api(w, r)
	case strings.HasPrefix(r.URL.Path, "/link/"):
		s.link(w, r)
	case strings.HasPrefix(r.URL.Path, "/raw/"):
		s.raw(w, r)
	default:
		http.NotFound(w, r)
	}
}

// recorder keeps the status a handler answered with.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// logged writes one line a request to stderr, for the tests to read: the
// protocol, method, host, request URI and status.
func logged(handler http.Handler) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		handler.ServeHTTP(rec, r)
		mu.Lock()
		fmt.Fprintln(os.Stderr, "served", r.Proto, r.Method, r.Host, r.RequestURI, rec.status)
		mu.Unlock()
	})
}

func serve(handler http.Handler, ln net.Listener, secure bool) {
	server := &http.Server{Handler: logged(handler)}
	var err error
	if secure {
		err = server.ServeTLS(ln, *certFile, *keyFile)
	} else {
		err = server.Serve(ln)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	flag.Parse()
	var handler http.Handler
	switch *mode {
	case "s3":
		if *access == "" || *secret == "" || *bucket == "" {
			fmt.Fprintln(os.Stderr, "-access, -secret and -bucket are required")
			os.Exit(2)
		}
		s := &store{objects: map[string][]byte{}, requests: map[string]int{}}
		handler = http.HandlerFunc(s.serveS3)
	case "template":
		if *refresh == "" && *static == "" {
			fmt.Fprintln(os.Stderr, "-refresh-token or -static-token is required")
			os.Exit(2)
		}
		handler = &templateStore{objects: map[string][]byte{}, links: map[string]string{},
			tokens: map[string]bool{}}
	default:
		fmt.Fprintln(os.Stderr, "unknown -mode", *mode)
		os.Exit(2)
	}
	addresses := map[string]string{}
	plain, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	addresses["http"] = plain.Addr().String()
	go serve(handler, plain, false)
	if *certFile != "" {
		secure, err := net.Listen("tcp", *tlsAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		addresses["https"] = secure.Addr().String()
		go serve(handler, secure, true)
	}
	out, _ := json.Marshal(addresses)
	fmt.Println(string(out))
	select {}
}
