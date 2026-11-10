// Records what Xray-core v26.11.9's XDRIVE transport and the Go library
// under it make of the HTTP storages: the S3 URL and SigV4 headers of a
// request (s3Storage.target and sign at a fixed time, with
// ValidateS3Config and objectKey), the S3 answers it reads (s3ListPage and
// s3ErrorCode), template decoding and checking (newTemplateStorage), subst,
// jsonString and jsonNumber, http.ParseTime on the dates a Retry-After
// header may carry, Go's regexp as a template's namesRegex runs,
// net/url's Parse, ResolveReference and String, http.Client's redirect
// policy, driven through a RoundTripper that answers from a script, and the
// frames Go's HTTP/2 client writes for a request, read over a pipe. Nothing
// touches the network or the clock, so a fresh run matches
// tests/fixtures/xdrive/http-vectors.json byte for byte.
//
// It runs inside the package next to wal_oracle_test.go, added the same way:
//
//	go -C <pinned checkout> test -overlay overlay.json \
//	    ./transport/internet/xdrive -run TestXrayRustHTTPOracle
//
// with XDRIVE_HTTP_ORACLE_OUT naming the output file.
package xdrive

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type xrayRustS3Case struct {
	Name      string      `json:"name"`
	Endpoint  string      `json:"endpoint"`
	Region    string      `json:"region"`
	Bucket    string      `json:"bucket"`
	PathStyle bool        `json:"pathStyle"`
	Folder    string      `json:"folder"`
	Secrets   []string    `json:"secrets"`
	Method    string      `json:"method"`
	Object    string      `json:"object"`
	Query     [][2]string `json:"query"`
	Body      string      `json:"body"`
	Now       int64       `json:"now"`
	Error     string      `json:"error"`
	URL       string      `json:"url"`
	Headers   [][2]string `json:"headers"`
}

type xrayRustListCase struct {
	Payload   string   `json:"payload"`
	OK        bool     `json:"ok"`
	Truncated bool     `json:"truncated"`
	Next      string   `json:"next"`
	Keys      []string `json:"keys"`
	Prefixes  []string `json:"prefixes"`
	ErrorCode string   `json:"errorCode"`
}

type xrayRustOp struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Headers    [][2]string `json:"headers"`
	Body       string      `json:"body"`
	NamesRegex string      `json:"namesRegex"`
	HrefPath   string      `json:"hrefPath"`
	HrefMethod string      `json:"hrefMethod"`
}

type xrayRustTemplateCase struct {
	Template    string      `json:"template"`
	Error       string      `json:"error"`
	Flatten     bool        `json:"flatten"`
	Concurrency int         `json:"concurrency"`
	AuthType    string      `json:"authType"`
	AuthHeader  [][2]string `json:"authHeader"`
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	TokenURL    string      `json:"tokenUrl"`
	Form        [][2]string `json:"form"`
	TokenPath   string      `json:"tokenPath"`
	ExpiryPath  string      `json:"expiryPath"`
	Put         xrayRustOp  `json:"put"`
	Get         xrayRustOp  `json:"get"`
	Delete      xrayRustOp  `json:"delete"`
	List        xrayRustOp  `json:"list"`
	RetryStatus []int       `json:"retryStatus"`
	RateReason  string      `json:"rateReason"`
}

type xrayRustSubstCase struct {
	Template string      `json:"template"`
	Vars     [][2]string `json:"vars"`
	Out      string      `json:"out"`
}

type xrayRustJSONPathCase struct {
	Payload string `json:"payload"`
	Path    string `json:"path"`
	String  string `json:"string"`
	Number  int64  `json:"number"`
}

type xrayRustHTTPDateCase struct {
	Raw   string `json:"raw"`
	OK    bool   `json:"ok"`
	Unix  int64  `json:"unix"`
	Nanos int    `json:"nanos"`
}

type xrayRustRegexpCase struct {
	Pattern   string       `json:"pattern"`
	Error     string       `json:"error"`
	NumSubexp int          `json:"numSubexp"`
	Texts     []string     `json:"texts"`
	Matches   [][][]string `json:"matches"`
}

type xrayRustURLCase struct {
	Base     string `json:"base"`
	Ref      string `json:"ref"`
	Error    string `json:"error"`
	Resolved string `json:"resolved"`
}

type xrayRustHop struct {
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers [][2]string `json:"headers"`
	Body    string      `json:"body"`
}

type xrayRustAnswer struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
}

type xrayRustRedirectCase struct {
	Name    string           `json:"name"`
	Method  string           `json:"method"`
	URL     string           `json:"url"`
	Headers [][2]string      `json:"headers"`
	Body    string           `json:"body"`
	Answers []xrayRustAnswer `json:"answers"`
	Hops    []xrayRustHop    `json:"hops"`
	Status  int              `json:"status"`
	Error   bool             `json:"error"`
}

type xrayRustData struct {
	Length    int  `json:"length"`
	EndStream bool `json:"endStream"`
}

type xrayRustH2Case struct {
	Method       string         `json:"method"`
	URL          string         `json:"url"`
	Headers      [][2]string    `json:"headers"`
	BodyBytes    int            `json:"bodyBytes"`
	Settings     [][2]uint32    `json:"settings"`
	WindowUpdate uint32         `json:"windowUpdate"`
	EndStream    bool           `json:"endStream"`
	PseudoHex    string         `json:"pseudoHex"`
	Pseudo       [][2]string    `json:"pseudo"`
	Regular      [][2]string    `json:"regular"`
	Data         []xrayRustData `json:"data"`
}

type xrayRustSlotCase struct {
	Seq     int64  `json:"seq"`
	Mode    int    `json:"mode"`
	Data    []byte `json:"data"`
	Encoded string `json:"encoded"`
}

type xrayRustSlotDecode struct {
	Description string `json:"description"`
	OK          bool   `json:"ok"`
	Seq         int64  `json:"seq"`
	Mode        int    `json:"mode"`
	Size        int    `json:"size"`
	CRC         uint32 `json:"crc"`
	Data        []byte `json:"data"`
}

type xrayRustRingCase struct {
	Payload string     `json:"payload"`
	OK      bool       `json:"ok"`
	Up      [][]string `json:"up"`
	Down    [][]string `json:"down"`
	Marshal string     `json:"marshal"`
}

type xrayRustDriveRequest struct {
	Op          string `json:"op"`
	Method      string `json:"method"`
	Target      string `json:"target"`
	ContentType string `json:"contentType"`
	Auth        string `json:"auth"`
	Body        []byte `json:"body"`
	Status      int    `json:"status"`
	Answer      string `json:"answer"`
}

type xrayRustDriveStep struct {
	Op     string   `json:"op"`
	Name   string   `json:"name"`
	Data   []byte   `json:"data"`
	Result []byte   `json:"result"`
	Names  []string `json:"names"`
	Error  string   `json:"error"`
}

type xrayRustDrive struct {
	Quotes      [][2]string            `json:"quotes"`
	Multipart   []byte                 `json:"multipart"`
	RateLimited []xrayRustRateCase     `json:"rateLimited"`
	Steps       []xrayRustDriveStep    `json:"steps"`
	Requests    []xrayRustDriveRequest `json:"requests"`
}

type xrayRustRateCase struct {
	Payload string `json:"payload"`
	Limited bool   `json:"limited"`
}

type xrayRustHTTPVectors struct {
	S3        []xrayRustS3Case       `json:"s3"`
	Lists     []xrayRustListCase     `json:"lists"`
	Templates []xrayRustTemplateCase `json:"templates"`
	Subst     []xrayRustSubstCase    `json:"subst"`
	JSONPaths []xrayRustJSONPathCase `json:"jsonPaths"`
	HTTPDates []xrayRustHTTPDateCase `json:"httpDates"`
	Regexps   []xrayRustRegexpCase   `json:"regexps"`
	URLs      []xrayRustURLCase      `json:"urls"`
	Redirects []xrayRustRedirectCase `json:"redirects"`
	H2        []xrayRustH2Case       `json:"h2"`
	Slots     []xrayRustSlotCase     `json:"slots"`
	Decodes   []xrayRustSlotDecode   `json:"slotDecodes"`
	Rings     []xrayRustRingCase     `json:"rings"`
	Drive     xrayRustDrive          `json:"drive"`
}

func xrayRustPairs(m map[string]string) [][2]string {
	pairs := make([][2]string, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, [2]string{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	return pairs
}

func xrayRustHeaderPairs(h http.Header) [][2]string {
	pairs := [][2]string{}
	for k, vv := range h {
		for _, v := range vv {
			pairs = append(pairs, [2]string{k, v})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	return pairs
}

func xrayRustS3(t *testing.T) []xrayRustS3Case {
	keys := []string{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	withToken := append(append([]string(nil), keys...), "Fwo//token  with   spaces=")
	now := int64(1794200000)
	cases := []xrayRustS3Case{
		{Name: "put path-style", Endpoint: "https://s3.example.com", Bucket: "my-bucket", PathStyle: true,
			Folder: "xdrive", Secrets: keys, Method: "PUT", Object: "sessions/1-abc", Body: "data"},
		{Name: "get virtual-hosted with port", Endpoint: "http://minio.local:9000/", Region: "eu-central-1",
			Bucket: "bucket.with.dots", Folder: "a/b/", Secrets: keys, Method: "GET",
			Object: "streams/s/c2s/000000001.seg"},
		{Name: "list with token", Endpoint: "https://s3.example.com/base%2Fpath/x y", Region: "us-west-2",
			Bucket: "b1", PathStyle: true, Folder: "root", Secrets: withToken, Method: "GET",
			Query: [][2]string{{"list-type", "2"}, {"prefix", "root/streams/a b+c/"}, {"max-keys", "1000"},
				{"delimiter", "/"}, {"continuation-token", "1/ab+cd=="}}},
		{Name: "delete in an escaped folder", Endpoint: "https://s3.example.com", Bucket: "b2", PathStyle: true,
			Folder: "dir with space/ü", Secrets: keys, Method: "DELETE", Object: "sessions/x"},
		{Name: "region auto", Endpoint: "https://r2.example.com", Region: "auto", Bucket: "b3", PathStyle: true,
			Folder: "f", Secrets: keys, Method: "PUT", Object: "streams/a/s2c/000000002.end"},
		{Name: "invalid object name", Endpoint: "https://s3.example.com", Bucket: "b4", PathStyle: true,
			Folder: "f", Secrets: keys, Method: "GET", Object: "../escape"},
		{Name: "object key too long", Endpoint: "https://s3.example.com", Bucket: "b5", PathStyle: true,
			Folder: strings.Repeat("k", 1020), Secrets: keys, Method: "GET", Object: "sessions/x"},
		{Name: "missing secret", Endpoint: "https://s3.example.com", Bucket: "b6", PathStyle: true,
			Folder: "f", Secrets: keys[:1], Method: "GET", Object: "x"},
		{Name: "bad bucket", Endpoint: "https://s3.example.com", Bucket: "Bad_Bucket", Folder: "f",
			Secrets: keys, Method: "GET", Object: "x"},
	}
	for i := range cases {
		c := &cases[i]
		c.Now = now
		config := &Config{Service: "s3", RemoteFolder: c.Folder, Secrets: c.Secrets,
			S3: &S3Config{Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, PathStyle: c.PathStyle}}
		storage, err := newS3Storage(nil, config)
		if err != nil {
			c.Error = err.Error()
			continue
		}
		key := ""
		if c.Object != "" {
			if key, err = storage.objectKey(c.Object); err != nil {
				c.Error = err.Error()
				continue
			}
		}
		query := url.Values{}
		for _, kv := range c.Query {
			query.Set(kv[0], kv[1])
		}
		target := storage.target(key, query)
		req, err := http.NewRequest(c.Method, target, bytes.NewReader([]byte(c.Body)))
		if err != nil {
			t.Fatal(err)
		}
		if c.Method == http.MethodPut {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		storage.sign(req, s3Hash([]byte(c.Body)), time.Unix(c.Now, 0))
		c.URL = req.URL.String()
		c.Headers = xrayRustHeaderPairs(req.Header)
	}
	return cases
}

func xrayRustLists() []xrayRustListCase {
	payloads := []string{
		`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><IsTruncated>true</IsTruncated><NextContinuationToken>tok&amp;1</NextContinuationToken><Contents><Key>root/a</Key><Size>1</Size></Contents><Contents><Key>root/b</Key></Contents><CommonPrefixes><Prefix>root/streams/</Prefix></CommonPrefixes></ListBucketResult>`,
		`<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`,
		`<ListBucketResult><IsTruncated>1</IsTruncated><NextContinuationToken> spaced </NextContinuationToken></ListBucketResult>`,
		`<ListBucketResult><IsTruncated>yes</IsTruncated></ListBucketResult>`,
		`<ListBucketResult><IsTruncated> true </IsTruncated></ListBucketResult>`,
		`<ListBucketResult><Contents><Key>a<!-- c -->b<![CDATA[<c>]]></Key></Contents></ListBucketResult>`,
		`<ListBucketResult><Contents><Key>x</Key><Key>y</Key></Contents></ListBucketResult>`,
		`<ListBucketResult><Contents><Other><Key>nested</Key></Other><Key>k</Key></Contents></ListBucketResult>`,
		`<s3:ListBucketResult xmlns:s3="x"><s3:Contents><s3:Key>ns</s3:Key></s3:Contents></s3:ListBucketResult>`,
		`<ListBucketResultX><Contents><Key>k</Key></Contents></ListBucketResultX>`,
		`<ListBucketResult><Contents><Key>k</Key></Contents>`,
		`<ListBucketResult><Contents><Key>a&bogus;</Key></Contents></ListBucketResult>`,
		`<ListBucketResult><Contents><Key>&#x41;&#66;&lt;&gt;&quot;&apos;</Key></Contents></ListBucketResult>`,
		`<?xml version="1.0"?><!DOCTYPE x><ListBucketResult><Contents><Key>d</Key></Contents></ListBucketResult>`,
		`  <ListBucketResult/>`,
		``,
		`not xml`,
		`<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult><extra/>`,
		`<Error><Code>NoSuchKey</Code><Message>m</Message></Error>`,
		`<Error><Code> SlowDown </Code></Error>`,
		`<Error><Message>no code</Message></Error>`,
		`<Other><Code>X</Code></Other>`,
	}
	cases := make([]xrayRustListCase, 0, len(payloads))
	for _, payload := range payloads {
		c := xrayRustListCase{Payload: payload, Keys: []string{}, Prefixes: []string{}}
		var page s3ListPage
		if err := xml.Unmarshal([]byte(payload), &page); err == nil {
			c.OK = true
			c.Truncated = page.IsTruncated
			c.Next = page.NextContinuationToken
			for _, item := range page.Contents {
				c.Keys = append(c.Keys, item.Key)
			}
			for _, item := range page.CommonPrefixes {
				c.Prefixes = append(c.Prefixes, item.Prefix)
			}
		}
		c.ErrorCode = s3ErrorCode([]byte(payload))
		cases = append(cases, c)
	}
	return cases
}

func xrayRustOpOf(op opTemplate) xrayRustOp {
	return xrayRustOp{Method: op.Method, URL: op.URL, Headers: xrayRustPairs(op.Headers), Body: op.Body,
		NamesRegex: op.NamesRegex, HrefPath: op.HrefPath, HrefMethod: op.HrefMethod}
}

func xrayRustTemplates() []xrayRustTemplateCase {
	const ops = `"put":{"method":"PUT","url":"https://h/{folder}/{name}"},"get":{"url":"https://h/{folder}/{name}"},` +
		`"delete":{"method":"DELETE","url":"https://h/{folder}/{name}"},"list":{"url":"https://h/{folder}/","namesRegex":"<n>([^<]+)</n>"}`
	texts := []string{
		`{` + ops + `}`,
		`{"flatten":true,"concurrency":12,` + ops + `,"retry":{"status":[429,503,null],"rateReason":"error.errors.0.reason"}}`,
		`{"auth":{"type":"oauth2","tokenUrl":"https://t/token","form":{"grant_type":"refresh_token","refresh_token":"{secret0}","x":null},` +
			`"header":{"Authorization":"Bearer {token}"},"tokenPath":"a.b","expiryPath":"exp"},` + ops + `}`,
		`{"auth":{"type":"basic","username":"{secret0}","password":"{secret1}"},` + ops + `}`,
		`{"PUT":{"METHOD":"PUT","Url":"https://h/upper"},"Get":{"URL":"https://h/g"},"DELETE":{"url":"https://h/d"},` +
			`"List":{"URL":"https://h/l","NamesRegex":"(x)"},"FLATTEN":true}`,
		`{"put":{"url":"https://h/p"},"get":{"url":"https://h/g","hrefPath":"href","hrefMethod":"PUT"},"delete":{"url":"https://h/d"},` +
			`"list":{"url":"https://h/l","namesRegex":"(x)"},"unknown":{"a":1},"concurrency":-3}`,
		`{` + ops + `,"concurrency":1000}`,
		`{` + ops + `,"concurrency":1.5}`,
		`{` + ops + `,"concurrency":"8"}`,
		`{` + ops + `,"concurrency":1e2}`,
		`{` + ops + `,"flatten":"true"}`,
		`{` + ops + `,"auth":null,"retry":null}`,
		`{` + ops + `,"auth":[]}`,
		`{"put":{"url":"https://h/p","headers":{"A":1}},"get":{"url":"g"},"delete":{"url":"d"},"list":{"url":"l","namesRegex":"(x)"}}`,
		`{"put":{"url":"p"},"get":{"url":"g"},"delete":{"url":"d"},"list":{"url":"l"}}`,
		`{"put":{"url":"p"},"get":{"url":"g"},"delete":{"url":"d"},"list":{"url":"l","namesRegex":"x"}}`,
		`{"put":{"url":"p"},"get":{"url":"g"},"delete":{"url":"d"},"list":{"url":"l","namesRegex":"(x"}}`,
		`{"put":{"url":"p"},"get":{"url":"g"},"list":{"url":"l","namesRegex":"(x)"}}`,
		`{"put":{"url":"p"},"get":{"url":""},"delete":{"url":"d"},"list":{"url":"l","namesRegex":"(x)"}}`,
		`{"put":{"url":"p","url":"p2"},"get":{"url":"g"},"delete":{"url":"d"},"list":{"url":"l","namesRegex":"(x)"},"put":{"url":"p3"}}`,
		`null`,
		`[]`,
		`"text"`,
		`{` + ops + `} trailing`,
		`{` + ops + `,"retry":{"status":[1.5]}}`,
		`{` + ops + `,"retry":{"status":"429"}}`,
	}
	cases := make([]xrayRustTemplateCase, 0, len(texts))
	for _, text := range texts {
		c := xrayRustTemplateCase{Template: text, AuthHeader: [][2]string{}, Form: [][2]string{}, RetryStatus: []int{}}
		storage, err := newTemplateStorage(nil, &Config{Service: "template", RemoteFolder: "f", Template: text})
		if err != nil {
			c.Error = err.Error()
			cases = append(cases, c)
			continue
		}
		tmpl := storage.tmpl
		c.Flatten, c.Concurrency = tmpl.Flatten, cap(storage.inflight)
		c.AuthType, c.AuthHeader = tmpl.Auth.Type, xrayRustPairs(tmpl.Auth.Header)
		c.Username, c.Password, c.TokenURL = tmpl.Auth.Username, tmpl.Auth.Password, tmpl.Auth.TokenURL
		c.Form, c.TokenPath, c.ExpiryPath = xrayRustPairs(tmpl.Auth.Form), tmpl.Auth.TokenPath, tmpl.Auth.ExpiryPath
		c.Put, c.Get, c.Delete, c.List = xrayRustOpOf(tmpl.Put), xrayRustOpOf(tmpl.Get), xrayRustOpOf(tmpl.Delete), xrayRustOpOf(tmpl.List)
		if tmpl.Retry.Status != nil {
			c.RetryStatus = tmpl.Retry.Status
		}
		c.RateReason = tmpl.Retry.RateReason
		cases = append(cases, c)
	}
	return cases
}

func xrayRustSubst() []xrayRustSubstCase {
	cases := []xrayRustSubstCase{
		{Template: "https://h/{folder}/{name}?a={secret0}&b={secret1}", Vars: [][2]string{{"folder", "root dir"},
			{"name", "streams~s~c2s~000000001.seg"}, {"secret0", "s/0"}, {"secret1", "x&y"}}},
		{Template: "{unknown}/{name}/{name}", Vars: [][2]string{{"name", "n"}}},
		{Template: "no braces", Vars: [][2]string{{"name", "n"}}},
		{Template: "", Vars: [][2]string{{"name", "n"}}},
		{Template: "{data}", Vars: [][2]string{{"data", "AAEC/w=="}}},
		{Template: "{ name }{name", Vars: [][2]string{{"name", "n"}}},
	}
	for i := range cases {
		vars := map[string]string{}
		for _, kv := range cases[i].Vars {
			vars[kv[0]] = kv[1]
		}
		cases[i].Out = subst(cases[i].Template, vars)
	}
	return cases
}

func xrayRustJSONPaths() []xrayRustJSONPathCase {
	// Numbers stay inside int64: past it, int64(float64) is the machine's
	// answer (arm64 saturates, amd64 gives the minimum), and the fixture
	// must come out the same on both.
	payload := `{"access_token":"tok","expires_in":3599.9,"neg":-2.7,"big":1e18,"a":{"b":{"c":"deep","n":7}},` +
		`"arr":[1],"s":"7","null":null,"t":true,"dup":"a","dup":"b"}`
	paths := []string{"access_token", "expires_in", "neg", "big", "a.b.c", "a.b.n", "a.b", "arr.0", "s", "null",
		"t", "dup", "missing", "a..b", ""}
	cases := []xrayRustJSONPathCase{}
	for _, path := range paths {
		cases = append(cases, xrayRustJSONPathCase{Payload: payload, Path: path})
	}
	for _, payload := range []string{"not json", `["x"]`, `"str"`, `{"x":"\u00e9\ud83d\ude00"}`, "{\"x\":\"a\xffb\"}"} {
		cases = append(cases, xrayRustJSONPathCase{Payload: payload, Path: "x"})
	}
	for i := range cases {
		cases[i].String = jsonString([]byte(cases[i].Payload), cases[i].Path)
		cases[i].Number = jsonNumber([]byte(cases[i].Payload), cases[i].Path)
	}
	return cases
}

// The dates a Retry-After header may carry, read by http.ParseTime as the
// S3 storage reads them. A zone abbreviation that names the local zone
// takes its offset, so the run reads them as if the machine were on UTC.
func xrayRustHTTPDates() []xrayRustHTTPDateCase {
	local := time.Local
	time.Local = time.UTC
	defer func() { time.Local = local }()
	raws := []string{
		"", "0", "3", "-5", "garbage",
		// http.TimeFormat
		"Mon, 02 Jan 2026 15:04:05 GMT",
		"mon, 02 JAN 2026 15:04:05 GMT",
		"Mon, 02 Jan 2026 15:04:05 gmt",
		"Mon,   02 Jan 2026 15:04:05   GMT",
		"Mon,02 Jan 2026 15:04:05 GMT",
		"Xyz, 02 Jan 2026 15:04:05 GMT",
		"Fri, 02 Jan 2026 15:04:05 GMT",
		"Monday, 02 Jan 2026 15:04:05 GMT",
		"Mon, 2 Jan 2026 15:04:05 GMT",
		"Mon, 00 Jan 2026 15:04:05 GMT",
		"Mon, 31 Apr 2026 15:04:05 GMT",
		"Mon, 30 Feb 2026 15:04:05 GMT",
		"Mon, 29 Feb 2024 15:04:05 GMT",
		"Mon, 29 Feb 2100 15:04:05 GMT",
		"Mon, 29 Feb 2000 15:04:05 GMT",
		"Mon, 02 Jan 99999 15:04:05 GMT",
		"Mon, 02 Jan 999999999999999999999 15:04:05 GMT",
		"Mon, 02 Jan 206 15:04:05 GMT",
		"Mon, 02 Jan +2026 15:04:05 GMT",
		"Mon, 02 Jan 20a6 15:04:05 GMT",
		"Mon, 02 Jan 0000 15:04:05 GMT",
		"Mon, 02 Jan 9999 23:59:59 GMT",
		"Mon, 02 Jan 2026 5:04:05 GMT",
		"Mon, 02 Jan 2026 24:00:00 GMT",
		"Mon, 02 Jan 2026 15:4:05 GMT",
		"Mon, 02 Jan 2026 15:04:60 GMT",
		"Mon, 02 Jan 2026 15:04:05.123456789123 GMT",
		"Mon, 02 Jan 2026 15:04:05,5 GMT",
		"Mon, 02 Jan 2026 15:04:05. GMT",
		"Mon, 02 Jan 2026 15:04:05 GMT ",
		"Mon, 02 Jän 2026 15:04:05 GMT",
		"Mön, 02 Jan 2026 15:04:05 GMT",
		// time.RFC850
		"Monday, 02-Jan-26 15:04:05 GMT",
		"monday, 02-jan-26 15:04:05 GMT",
		"Sunday, 02-Jan-70 00:00:00 GMT",
		"Monday, 02-Jan-68 15:04:05 GMT",
		"Monday, 02-Jan-69 15:04:05 GMT",
		"Monday, 02-Jan-2026 15:04:05 GMT",
		"Monday, 02-Jan--5 15:04:05 GMT",
		"Monday, 02-Jan-+5 15:04:05 GMT",
		"Monday, 02-Jan-26 15:04:05 UTC",
		"Monday, 02-Jan-26 15:04:05 UTCX",
		"Monday, 02-Jan-26 15:04:05 PST",
		"Monday, 02-Jan-26 15:04:05 GMT+3",
		"Monday, 02-Jan-26 15:04:05 GMT-0",
		"Monday, 02-Jan-26 15:04:05 GMT+30",
		"Monday, 02-Jan-26 15:04:05 GMT+",
		"Monday, 02-Jan-26 15:04:05 +03",
		"Monday, 02-Jan-26 15:04:05 -0330",
		"Monday, 02-Jan-26 15:04:05 +033",
		"Monday, 02-Jan-26 15:04:05 +",
		"Monday, 02-Jan-26 15:04:05 ABCDT",
		"Monday, 02-Jan-26 15:04:05 ABCDE",
		"Monday, 02-Jan-26 15:04:05 ABCT",
		"Monday, 02-Jan-26 15:04:05 ABCD",
		"Monday, 02-Jan-26 15:04:05 WITA",
		"Monday, 02-Jan-26 15:04:05 ChST",
		"Monday, 02-Jan-26 15:04:05 MeST",
		"Monday, 02-Jan-26 15:04:05 ABCDEF",
		"Monday, 02-Jan-26 15:04:05 AB",
		"Monday, 02-Jan-26 15:04:05 abc",
		"Monday, 02-Jan-26 15:04:05",
		"Mon, 02-Jan-26 15:04:05 GMT",
		// time.ANSIC
		"Mon Jan  2 15:04:05 2026",
		"Mon Jan 2 15:04:05 2026",
		"Mon Jan 02 15:04:05 2026",
		"Mon Jan 123 15:04:05 2026",
		"Mon Jan  2 15:04:05.5 2026",
		"Mon Jan  2 15:04:05 99999",
		"Mon Jan  2 15:04:05 2026 ",
		"Mon Jan  2 15:04:05 2026 GMT",
		"Mon Feb 29 15:04:05 2023",
		" Mon Jan  2 15:04:05 2026",
	}
	cases := []xrayRustHTTPDateCase{}
	for _, raw := range raws {
		c := xrayRustHTTPDateCase{Raw: raw}
		if at, err := http.ParseTime(raw); err == nil {
			c.OK, c.Unix, c.Nanos = true, at.Unix(), at.Nanosecond()
		}
		cases = append(cases, c)
	}
	return cases
}

func xrayRustRegexps() []xrayRustRegexpCase {
	listing := `{"entries":[{"name":"sessions~1-a"},{"name":"streams~s~c2s~000000001.seg"}],"next":null}`
	dav := `<d:response><d:href>/f/a%20b</d:href></d:response><d:response><d:href>/f/c</d:href></d:response>`
	patterns := map[string][]string{
		`"name":"([^"]+)"`:            {listing, `{"name":""}`},
		`<d:href>/f/([^<]+)</d:href>`: {dav},
		`(?i)<KEY>(.*?)</key>`:        {`<key>a</KEY><Key>b</kEy>`},
		`\bname=(\w+)`:                {`name=a1 rename=b2 name=é3`},
		`(?s)<a>(.*)</a>`:             {"<a>x\ny</a><a>z</a>"},
		`(?U)x(a+)`:                   {`xaaa`},
		`(\d{2,3})`:                   {`1 12 1234 ١٢٣`},
		`x{2}(y)`:                     {`xxy xy`},
		`a{,3}(b)`:                    {`a{,3}b aab`},
		`(\pL+)(\d)?`:                 {`héllo1 wörld`},
		`([[:alpha:]]+)(\d)`:          {`abc1 é2`},
		`\Qa.b\E(c)`:                  {`a.bc axbc`},
		`(?P<n>a)(?<m>b)`:             {`ab`},
		`()`:                          {`ab`},
		`(a*)`:                        {`baaac`},
		`(?m)^(\w+)$`:                 {"one\ntwo\n"},
		`(x)|(y)`:                     {`xy`},
		`[^\x00-\x7f](.)`:             {`aéb`},
		`\$(\d+)\.(\d\d)`:             {`$12.50 and $3.05`},
		`(\x{1F600})`:                 {"😀"},
		`([\w-]+)@`:                   {`a-b@c`},
		`\A(a)|(b)\z`:                 {`ab`},
		`(`:                           nil,
		`a**`:                         nil,
		`a++`:                         nil,
		`x{1001}`:                     nil,
		`[z-a]`:                       nil,
		`\8`:                          nil,
		`(?<>a)`:                      nil,
		`\C`:                          nil,
		`(?i`:                         nil,
		`[[:word:]]`:                  {`a_1`},
		`[[:foo:]]`:                   nil,
		`(?z)a`:                       nil,
		`\pX`:                         nil,
		`x{2,1}`:                      nil,
		`a{1000}(b)`:                  {`b`},
		`((((((((((a))))))))))`:       {`a`},
		`[a-c&&b]`:                    {`&b`},
		`(\w+)\s*=\s*"([^"]*)"`:       {`k = "v" x="y"`},
		`(?:a|b)+(c)`:                 {`abac`},
		`\.(\w+)$`:                    {`file.seg`},
		"(é)":                         {"é é"},
		`(\S+)\s`:                     {"a b c"},
		`([^\n]+)`:                    {"l1\nl2"},
		`(.)`:                         {"a\xffb"},
		`\d+(\.\d+)?(e[+-]?\d+)?`:     {`1.5e+3 2`},
		`(a|ab)(c|bcd)(d*)`:           {`abcd`},
		`^(\w+)`:                      {`ab cd`},
		`(?i)(STRASSE)`:               {`straße STRASSE`},
		`[\d\-a-f]+(z)`:               {`a-1z`},
		`\x41(\x{42})`:                {`AB`},
		`\101(.)`:                     {`AB`},
		`\0(.)`:                       {"\x00Q"},
		`(\cA)`:                       nil,
		`[\b](x)`:                     nil,
		`\z(x)`:                       {`x`},
		`(?-s:.)+(z)`:                 {"a\nz"},
		`(?i:A)(b)`:                   {`ab Ab aB`},
		`(?s-i)A(.)`:                  {"A\n"},
		`a(?#comment)(b)`:             nil,
	}
	keys := make([]string, 0, len(patterns))
	for p := range patterns {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	cases := make([]xrayRustRegexpCase, 0, len(keys))
	for _, p := range keys {
		c := xrayRustRegexpCase{Pattern: p, Texts: patterns[p], Matches: [][][]string{}}
		if c.Texts == nil {
			c.Texts = []string{}
		}
		re, err := regexp.Compile(p)
		if err != nil {
			c.Error = err.Error()
			cases = append(cases, c)
			continue
		}
		c.NumSubexp = re.NumSubexp()
		for _, text := range c.Texts {
			found := re.FindAllStringSubmatch(text, -1)
			if found == nil {
				found = [][]string{}
			}
			c.Matches = append(c.Matches, found)
		}
		cases = append(cases, c)
	}
	return cases
}

func xrayRustURLs() []xrayRustURLCase {
	base := "https://user:p%40ss@h.example:8443/a/b/c?q=1#frag"
	refs := []string{"", "d", "./d", "../d", "../../../../d", "/d/./e/../f", "?x=2", "#f2", "?", "//other/x",
		"http://x.example/y/../z", "https:/nohost", "g;x?y#s", "d%2Fe/f%20g", "..", ".", "d/", "../",
		"mailto:a@b", "%zz", "http://[::1]:80/p", "http://[::1", " d", "d e", "\x7f", "HTTP://UP.example/X",
		"#%7Ex", "d#a%2Fb%20c", "?q#f%41", "#"}
	cases := []xrayRustURLCase{}
	for _, ref := range refs {
		cases = append(cases, xrayRustURLCase{Base: base, Ref: ref})
	}
	for _, b := range []string{"http://h", "http://h/", "http://h/a%2Fb/c", "http://h/a?b", "mailto:x@y", "http://h/p#%7E"} {
		for _, ref := range []string{"d", "../d", "?z", ""} {
			cases = append(cases, xrayRustURLCase{Base: b, Ref: ref})
		}
	}
	for i := range cases {
		b, err := url.Parse(cases[i].Base)
		if err != nil {
			cases[i].Error = err.Error()
			continue
		}
		u, err := b.Parse(cases[i].Ref)
		if err != nil {
			cases[i].Error = err.Error()
			continue
		}
		cases[i].Resolved = u.String()
	}
	return cases
}

// xrayRustScript answers each request with the next scripted answer and
// keeps what reached it.
type xrayRustScript struct {
	answers []xrayRustAnswer
	hops    []xrayRustHop
}

func (s *xrayRustScript) RoundTrip(r *http.Request) (*http.Response, error) {
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	s.hops = append(s.hops, xrayRustHop{Method: r.Method, URL: r.URL.String(), Headers: xrayRustHeaderPairs(r.Header), Body: body})
	answer := s.answers[len(s.hops)-1]
	header := http.Header{}
	if answer.Location != "" {
		header.Set("Location", answer.Location)
	}
	return &http.Response{StatusCode: answer.Status, Header: header, Body: io.NopCloser(strings.NewReader("")),
		Request: r, ContentLength: 0}, nil
}

func xrayRustRedirects() []xrayRustRedirectCase {
	auth := [][2]string{{"Authorization", "Bearer t"}, {"Content-Type", "application/json"}, {"X-Custom", "1"},
		{"Cookie", "c=1"}}
	loop := []xrayRustAnswer{}
	for i := 0; i < 10; i++ {
		loop = append(loop, xrayRustAnswer{302, "/loop"})
	}
	cases := []xrayRustRedirectCase{
		{Name: "see other drops the body", Method: "PUT", URL: "https://api.example/v1/put", Headers: auth, Body: "data",
			Answers: []xrayRustAnswer{{303, "/v1/done?x=1"}, {200, ""}}},
		{Name: "found keeps get", Method: "GET", URL: "https://api.example/v1/get", Headers: auth,
			Answers: []xrayRustAnswer{{302, "https://cdn.api.example/blob"}, {301, "https://other.example/blob"}, {200, ""}}},
		{Name: "temporary keeps method and body", Method: "PUT", URL: "https://api.example/a/b", Headers: auth, Body: "data",
			Answers: []xrayRustAnswer{{307, "c"}, {308, "//api.example:8443/d"}, {201, ""}}},
		{Name: "post becomes get", Method: "POST", URL: "http://h.example/token", Headers: auth, Body: "form",
			Answers: []xrayRustAnswer{{302, "/next"}, {307, "/again"}, {200, ""}}},
		{Name: "head stays head", Method: "HEAD", URL: "http://h.example/x", Answers: []xrayRustAnswer{{301, "/y"}, {200, ""}}},
		{Name: "no location", Method: "GET", URL: "http://h.example/x", Answers: []xrayRustAnswer{{302, ""}}},
		{Name: "not modified", Method: "GET", URL: "http://h.example/x", Answers: []xrayRustAnswer{{304, "/y"}}},
		{Name: "https to http drops the referer", Method: "GET", URL: "https://h.example/x", Headers: auth,
			Answers: []xrayRustAnswer{{302, "http://h.example/y"}, {302, "http://h.example/z"}, {200, ""}}},
		{Name: "explicit referer", Method: "GET", URL: "https://h.example/x", Headers: [][2]string{{"Referer", "https://ref.example/"}},
			Answers: []xrayRustAnswer{{302, "/y"}, {200, ""}}},
		{Name: "user information", Method: "GET", URL: "https://u:p@h.example/x", Answers: []xrayRustAnswer{{302, "https://w:q@h.example/y"}, {302, "/z"}, {200, ""}}},
		{Name: "basic from the url only without authorization", Method: "GET", URL: "https://u:p@h.example/x", Headers: auth,
			Answers: []xrayRustAnswer{{200, ""}}},
		{Name: "subdomain then back keeps stripped", Method: "GET", URL: "https://example.com/x", Headers: auth,
			Answers: []xrayRustAnswer{{302, "https://a.example.com/y"}, {302, "https://evil.example/z"}, {302, "https://example.com/w"}, {200, ""}}},
		{Name: "port change strips nothing on the same host", Method: "GET", URL: "https://h.example/x", Headers: auth,
			Answers: []xrayRustAnswer{{302, "https://h.example:444/y"}, {200, ""}}},
		{Name: "ten requests at most", Method: "GET", URL: "http://h.example/start", Answers: loop},
		{Name: "bad location", Method: "GET", URL: "http://h.example/x", Answers: []xrayRustAnswer{{302, "http://[::1"}}},
		{Name: "fragment location", Method: "GET", URL: "http://h.example/x", Answers: []xrayRustAnswer{{302, "/y#frag"}, {302, "z"}, {200, ""}}},
	}
	for i := range cases {
		c := &cases[i]
		script := &xrayRustScript{answers: c.Answers}
		client := &http.Client{Transport: script}
		var body io.Reader
		if c.Body != "" {
			body = bytes.NewReader([]byte(c.Body))
		}
		req, err := http.NewRequest(c.Method, c.URL, body)
		if err != nil {
			panic(err)
		}
		for _, kv := range c.Headers {
			req.Header.Set(kv[0], kv[1])
		}
		resp, err := client.Do(req)
		c.Hops = script.hops
		if err != nil {
			c.Error = true
		} else {
			c.Status = resp.StatusCode
		}
		if c.Headers == nil {
			c.Headers = [][2]string{}
		}
	}
	return cases
}

func xrayRustCertificate(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"storage.example"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// xrayRustH2 sends each case through net/http as Xray-core's service client
// does, DialTLSContext over a pipe and ForceAttemptHTTP2 with
// SendPingTimeout, and reads what reaches the server: the client's SETTINGS
// and connection WINDOW_UPDATE, the request's header block and DATA frames.
// Go writes regular headers in its map's random order, so they come sorted.
func xrayRustH2(t *testing.T) []xrayRustH2Case {
	certificate := xrayRustCertificate(t)
	ua := [2]string{"User-Agent", "xray-rust-oracle/1"}
	cases := []xrayRustH2Case{
		{Method: "PUT", URL: "https://storage.example/v1/f/streams~a~c2s~000000001.seg", BodyBytes: 4,
			Headers: [][2]string{ua, {"Content-Type", "application/octet-stream"}, {"X-Custom", "1"}}},
		{Method: "GET", URL: "https://storage.example/v1/list?prefix=a%2Fb", Headers: [][2]string{ua, {"Authorization", "Bearer t"}}},
		{Method: "DELETE", URL: "https://bucket.storage.example:8443/key", Headers: [][2]string{ua}},
		{Method: "PUT", URL: "https://storage.example/big", BodyBytes: 40000, Headers: [][2]string{ua}},
		{Method: "GET", URL: "https://storage.example/r", Headers: [][2]string{ua, {"Range", "bytes=0-9"}}},
		{Method: "PUT", URL: "https://storage.example/empty", Headers: [][2]string{ua}},
		{Method: "POST", URL: "https://storage.example/token", BodyBytes: 7,
			Headers: [][2]string{ua, {"Content-Type", "application/x-www-form-urlencoded"}}},
	}
	for i := range cases {
		c := &cases[i]
		clientConn, serverConn := net.Pipe()
		transport := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn := tls.Client(clientConn, &tls.Config{ServerName: "storage.example", InsecureSkipVerify: true,
					NextProtos: []string{"h2", "http/1.1"}})
				return conn, conn.HandshakeContext(ctx)
			},
			ForceAttemptHTTP2: true,
			HTTP2:             &http.HTTP2Config{SendPingTimeout: 45 * time.Second},
		}
		go func() {
			var body io.Reader
			if c.BodyBytes > 0 {
				body = bytes.NewReader(bytes.Repeat([]byte{'x'}, c.BodyBytes))
			}
			req, _ := http.NewRequest(c.Method, c.URL, body)
			for _, kv := range c.Headers {
				req.Header.Set(kv[0], kv[1])
			}
			transport.RoundTrip(req)
		}()
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}})
		if err := server.Handshake(); err != nil {
			t.Fatal(err)
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil || string(preface) != http2.ClientPreface {
			t.Fatalf("preface %q: %v", preface, err)
		}
		framer := http2.NewFramer(nil, server)
		framer.SetMaxReadFrameSize(1 << 24)
		c.Data = []xrayRustData{}
		var block []byte
		done := false
		for !done {
			frame, err := framer.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					f.ForeachSetting(func(s http2.Setting) error {
						c.Settings = append(c.Settings, [2]uint32{uint32(s.ID), s.Val})
						return nil
					})
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					c.WindowUpdate = f.Increment
				}
			case *http2.HeadersFrame:
				block = append(block, f.HeaderBlockFragment()...)
				c.EndStream = f.StreamEnded()
				done = c.EndStream && f.HeadersEnded()
			case *http2.DataFrame:
				c.Data = append(c.Data, xrayRustData{len(f.Data()), f.StreamEnded()})
				done = f.StreamEnded()
			}
		}
		server.Close()
		fields, err := hpack.NewDecoder(4096, nil).DecodeFull(block)
		if err != nil {
			t.Fatal(err)
		}
		c.Regular = [][2]string{}
		var pseudo bytes.Buffer
		encoder := hpack.NewEncoder(&pseudo)
		for _, f := range fields {
			if strings.HasPrefix(f.Name, ":") {
				c.Pseudo = append(c.Pseudo, [2]string{f.Name, f.Value})
				encoder.WriteField(f)
			} else {
				c.Regular = append(c.Regular, [2]string{f.Name, f.Value})
			}
		}
		// A fresh encoder writes the leading pseudo-headers as the client did.
		if !bytes.HasPrefix(block, pseudo.Bytes()) {
			t.Fatalf("%s %s: pseudo-headers re-encode as %x, the block is %x", c.Method, c.URL, pseudo.Bytes(), block)
		}
		c.PseudoHex = hex.EncodeToString(pseudo.Bytes())
		sort.Slice(c.Regular, func(i, j int) bool {
			if c.Regular[i][0] != c.Regular[j][0] {
				return c.Regular[i][0] < c.Regular[j][0]
			}
			return c.Regular[i][1] < c.Regular[j][1]
		})
	}
	return cases
}

func xrayRustSlotVectors() ([]xrayRustSlotCase, []xrayRustSlotDecode) {
	cases := []xrayRustSlotCase{
		{Seq: 0, Mode: slotInline, Data: []byte("hello")},
		{Seq: 1, Mode: slotInline, Data: []byte{}},
		{Seq: 7, Mode: slotMedia, Data: bytes.Repeat([]byte{0xa5}, 15000)},
		{Seq: 8, Mode: slotEnd},
		{Seq: 9, Mode: slotErr},
		{Seq: -1, Mode: slotEnd},
		{Seq: 1 << 40, Mode: slotInline, Data: []byte{0, 1, 2, 255}},
	}
	descriptions := []string{"", "not base64!", "WERSVlNMMDE=",
		base64.StdEncoding.EncodeToString(append([]byte("XDRVSL02"), make([]byte, 17)...))}
	for i := range cases {
		c := &cases[i]
		c.Encoded = newSlotFrame(c.Seq, byte(c.Mode), c.Data).encode()
		descriptions = append(descriptions, c.Encoded)
	}
	// An inline frame whose segment is not what it says, a media frame with
	// bytes after its header, and a mode nobody knows.
	bad := newSlotFrame(3, slotInline, []byte("abc"))
	bad.crc ^= 1
	descriptions = append(descriptions, bad.encode())
	media := newSlotFrame(4, slotMedia, []byte("abc"))
	media.data = []byte("tail")
	descriptions = append(descriptions, media.encode())
	descriptions = append(descriptions, newSlotFrame(5, 9, []byte("x")).encode())
	decodes := []xrayRustSlotDecode{}
	for _, d := range descriptions {
		f, ok := decodeSlot(d)
		decodes = append(decodes, xrayRustSlotDecode{Description: d, OK: ok, Seq: f.seq, Mode: int(f.mode),
			Size: f.size, CRC: f.crc, Data: f.data})
	}
	return cases, decodes
}

func xrayRustRings() []xrayRustRingCase {
	r := ring{Up: slotTable{Slots: []string{"a", "b<&>"}, Watermark: "w1"}, Down: slotTable{Slots: []string{"c"}, Watermark: "w2"}}
	marshal, _ := json.Marshal(r)
	payloads := []string{string(marshal), `{"U":{"S":["a"],"W":"w"},"D":{"s":["c"],"w":"x"}}`,
		`{"u":{"s":[],"w":"w"},"d":{"s":["c"],"w":"x"}}`, `{"u":{"s":["a"],"w":""},"d":{"s":["c"],"w":"x"}}`,
		`{"u":{"s":["a",null],"w":"w"},"d":{"s":["c"],"w":"x"}}`, `{"u":{"s":"a","w":"w"},"d":{"s":["c"],"w":"x"}}`,
		`null`, ``, `{"u":null,"d":{"s":["c"],"w":"x"}}`}
	cases := []xrayRustRingCase{}
	for _, p := range payloads {
		c := xrayRustRingCase{Payload: p}
		if got, ok := decodeRing([]byte(p)); ok {
			c.OK = true
			c.Up = [][]string{got.Up.Slots, {got.Up.Watermark}}
			c.Down = [][]string{got.Down.Slots, {got.Down.Watermark}}
		}
		cases = append(cases, c)
	}
	cases[0].Marshal = string(marshal)
	return cases
}

// xrayRustDriveScript answers each request with the next canned answer and
// keeps what reached it, the op being the storage call under way.
type xrayRustDriveScript struct {
	op       *string
	answers  []xrayRustDriveRequest
	requests []xrayRustDriveRequest
}

func (s *xrayRustDriveScript) RoundTrip(r *http.Request) (*http.Response, error) {
	body := []byte{}
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	i := len(s.requests)
	answer := s.answers[i]
	s.requests = append(s.requests, xrayRustDriveRequest{Op: *s.op, Method: r.Method, Target: r.URL.RequestURI(),
		ContentType: r.Header.Get("Content-Type"), Auth: r.Header.Get("Authorization"), Body: body,
		Status: answer.Status, Answer: answer.Answer})
	return &http.Response{StatusCode: answer.Status, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(answer.Answer)), Request: r}, nil
}

// xrayRustDriveScenario runs driveStorage's own calls one after another
// against canned answers, so that the order of the requests is fixed.
func xrayRustDriveScenario(t *testing.T) ([]xrayRustDriveStep, []xrayRustDriveRequest) {
	answers := []xrayRustDriveRequest{
		{Status: 200, Answer: `{"access_token":"tok-1","expires_in":3600}`},
		{Status: 200, Answer: `{"id":"f1"}`},
		{Status: 200, Answer: `{"id":"f2","name":"streams~s~c2s~000000001.seg"}`},
		{Status: 200, Answer: ``},
		{Status: 200, Answer: `{"description":"ZGF0YQ=="}`},
		{Status: 200, Answer: `{"files":[{"id":"f3","name":"streams~s~s2c~000000001.seg","description":"b25l"},{"id":"f4","name":"streams~s~s2c~sub~x","description":""}],"nextPageToken":"p2"}`},
		{Status: 200, Answer: `{"files":[{"id":"f5","name":"streams~s~s2c~000000002.end"}]}`},
		{Status: 403, Answer: `{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}`},
		{Status: 200, Answer: `{"files":[]}`},
		{Status: 200, Answer: `{"files":[{"id":"f6","name":"streams~t~a"}]}`},
		{Status: 204, Answer: ``},
		{Status: 401, Answer: ``},
		{Status: 200, Answer: `{"access_token":"tok-2","expires_in":30}`},
		{Status: 200, Answer: `{"id":"s0"}`},
		{Status: 200, Answer: `{"id":"s0"}`},
		{Status: 200, Answer: `{"id":"s0"}`},
		{Status: 200, Answer: `{"description":"frame"}`},
		{Status: 200, Answer: `body`},
		{Status: 404, Answer: ``},
	}
	op := ""
	script := &xrayRustDriveScript{op: &op, answers: answers}
	config := &Config{Service: "google-drive", RemoteFolder: "folder'id\\", Secrets: []string{"client id", "secret/+", "refresh&"}}
	storage, err := newDriveStorage(nil, config)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: script}
	storage.client, storage.tokenClient = client, client
	storage.tokenURL = "https://drive.test/token"
	storage.filesURL = "https://drive.test/drive/v3/files"
	storage.uploadURL = "https://drive.test/upload/drive/v3/files?uploadType=multipart&fields=id,name"
	storage.backoff = time.Millisecond
	ctx := context.Background()
	steps := []xrayRustDriveStep{}
	errText := func(err error) string {
		if err == nil {
			return ""
		}
		return "error"
	}
	run := func(step xrayRustDriveStep, call func() ([]byte, []string, error)) {
		op = step.Op
		result, names, err := call()
		step.Result, step.Names, step.Error = result, names, errText(err)
		if step.Names == nil {
			step.Names = []string{}
		}
		steps = append(steps, step)
	}
	run(xrayRustDriveStep{Op: "put", Name: "sessions/1-abc", Data: []byte("data")}, func() ([]byte, []string, error) {
		return nil, nil, storage.Put(ctx, "sessions/1-abc", []byte("data"))
	})
	large := bytes.Repeat([]byte{7}, 12001)
	run(xrayRustDriveStep{Op: "put", Name: "streams/s/c2s/000000001.seg", Data: large}, func() ([]byte, []string, error) {
		return nil, nil, storage.Put(ctx, "streams/s/c2s/000000001.seg", large)
	})
	run(xrayRustDriveStep{Op: "get", Name: "sessions/1-abc"}, func() ([]byte, []string, error) {
		data, err := storage.Get(ctx, "sessions/1-abc")
		return data, nil, err
	})
	run(xrayRustDriveStep{Op: "list", Name: "streams/s/s2c"}, func() ([]byte, []string, error) {
		entries, err := storage.List(ctx, "streams/s/s2c")
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name+"="+string(e.Inline))
		}
		sort.Strings(names)
		return nil, names, err
	})
	run(xrayRustDriveStep{Op: "delete", Name: "streams/t"}, func() ([]byte, []string, error) {
		return nil, nil, storage.Delete(ctx, "streams/t")
	})
	run(xrayRustDriveStep{Op: "makeSlot", Name: "streams/s/c2s/s0"}, func() ([]byte, []string, error) {
		id, err := storage.makeSlot(ctx, "streams/s/c2s/s0")
		return []byte(id), nil, err
	})
	run(xrayRustDriveStep{Op: "setSlot", Name: "s0"}, func() ([]byte, []string, error) {
		return nil, nil, storage.setSlot(ctx, "s0", "frame", nil)
	})
	run(xrayRustDriveStep{Op: "setSlotBody", Name: "s0", Data: []byte("body")}, func() ([]byte, []string, error) {
		return nil, nil, storage.setSlot(ctx, "s0", "frame", []byte("body"))
	})
	run(xrayRustDriveStep{Op: "readDescription", Name: "s0"}, func() ([]byte, []string, error) {
		d, err := storage.readDescription(ctx, "s0")
		return []byte(d), nil, err
	})
	run(xrayRustDriveStep{Op: "readBody", Name: "s0"}, func() ([]byte, []string, error) {
		data, err := storage.readBody(ctx, "s0")
		return data, nil, err
	})
	run(xrayRustDriveStep{Op: "readBody", Name: "gone"}, func() ([]byte, []string, error) {
		data, err := storage.readBody(ctx, "gone")
		return data, nil, err
	})
	if len(script.requests) != len(answers) {
		t.Fatalf("%d requests for %d answers", len(script.requests), len(answers))
	}
	return steps, script.requests
}

func TestXrayRustHTTPOracle(t *testing.T) {
	out := os.Getenv("XDRIVE_HTTP_ORACLE_OUT")
	if out == "" {
		t.Skip("XDRIVE_HTTP_ORACLE_OUT is not set")
	}
	vectors := xrayRustHTTPVectors{
		S3:        xrayRustS3(t),
		Lists:     xrayRustLists(),
		Templates: xrayRustTemplates(),
		Subst:     xrayRustSubst(),
		JSONPaths: xrayRustJSONPaths(),
		HTTPDates: xrayRustHTTPDates(),
		Regexps:   xrayRustRegexps(),
		URLs:      xrayRustURLs(),
		Redirects: xrayRustRedirects(),
		H2:        xrayRustH2(t),
		Rings:     xrayRustRings(),
	}
	vectors.Slots, vectors.Decodes = xrayRustSlotVectors()
	vectors.Drive.Steps, vectors.Drive.Requests = xrayRustDriveScenario(t)
	for _, v := range []string{`it's`, `a\\b`, `''`, `x`} {
		vectors.Drive.Quotes = append(vectors.Drive.Quotes, [2]string{v, quoteDriveValue(v)})
	}
	vectors.Drive.Multipart = multipartBody([]byte(`{"name":"n"}`), []byte{0, 1, 2})
	for _, p := range []string{`{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}`,
		`{"error":{"status":"RESOURCE_EXHAUSTED"}}`, `{"error":{"errors":[{"reason":"forbidden"}]}}`,
		`{"error":{"status":5,"errors":[{"reason":"rateLimitExceeded"}]}}`, `not json`, `{"ERROR":{"ERRORS":[{"REASON":"sharingRateLimitExceeded"}]}}`,
		`{"error":null}`, `{"error":{"errors":[null,{"reason":"rateLimitExceeded"}]}}`} {
		vectors.Drive.RateLimited = append(vectors.Drive.RateLimited, xrayRustRateCase{Payload: p, Limited: rateLimited([]byte(p))})
	}
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
