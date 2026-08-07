//go:build reality_oracle_version_distribution

// This oracle is intentionally invoked from the repository root with:
//
//	go run -C tools/reality-oracle/masquerade -tags reality_oracle_version_distribution . \
//	  > tests/fixtures/masquerade/version_distribution.json
//
// `-C` moves Go, not the shell, so the redirect above is still relative to the
// repository root while `-check` takes a path relative to this directory:
//
//	go run -C tools/reality-oracle/masquerade -tags reality_oracle_version_distribution . \
//	  -check ../../../tests/fixtures/masquerade/version_distribution.json
//
// See masquerade_headers.go for why this module is separate from the root one.
//
// It emits the *population* distribution of Xray's browser versions: what
// fraction of installs report each version, frozen to one instant. The header
// oracle next door cannot answer that, because a process only ever holds one
// machine's draw -- the version numbers in its fixtures are a property of the
// host that generated them.
//
// The Rust port draws its offsets from the OS CSPRNG rather than from Go's
// CPU-seeded `math/rand`, so it can never reproduce a particular machine's
// version. Matching this distribution is the whole of what it owes Xray, and
// this fixture is what
// `crates/xray-transport/tests/stream_http_headers_tests.rs` asserts against.
//
// # Why this file transcribes browser.go instead of calling it
//
// `utils.ChromeVersion` and friends read `time.Now()` and draw from a
// package-global PRNG that is already spent by the time `main` runs, so
// sampling a population needs both injectable. The transcription below is
// therefore verbatim apart from those two seams -- and `verifyTranscription`
// pins it to the real thing on every run, by replaying the reference
// implementation's own seed and clock and demanding the four version strings
// the package computed at init. A drift in `browser.go` fails the oracle rather
// than quietly moving the fixture.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/utils"
)

// The instant the distribution is frozen at: 2026-08-07 00:00:00 UTC.
//
// Any instant would do -- the point is that the Rust test evaluates its own
// distribution at the same one. A fixed instant also keeps `-check` meaningful,
// unlike the header fixtures, which drift with the calendar by design.
const fixtureUnix int64 = 1786060800

// The synthetic CPU grid the population is drawn over: 20 families x 40 models
// x 16 physical core counts x 2 threads-per-core, or 25 600 machines. Xray
// seeds one PRNG per machine from exactly these six attributes, so varying them
// is what varies the draw. The grid is wider than the plausible range on
// purpose; a narrower one would just resample the same FNV hashes.
const (
	familyLow, familyHigh     = 6, 26
	modelLow, modelHigh       = 60, 100
	physicalLow, physicalHigh = 1, 17
)

var safariMinorMap [25]int = [25]int{0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6}

// ---- browser.go, verbatim but for `now` and `rng` ---------------------------

func chromeVersion(rng *rand.Rand, now time.Time) int {
	var startVersion int = 144
	var timeStart int64 = time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeCurrent int64 = now.Unix() / 86400
	var timeDiff int = int((timeCurrent - timeStart - 35)) - int(math.Floor(math.Pow(rng.Float64(), 2)*105))
	return startVersion + (timeDiff / 35)
}

func curlVersion(rng *rand.Rand, now time.Time) string {
	var timeCurrent int64 = now.Unix() / 86400
	var timeStart int64 = time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeDiff int = int((timeCurrent - timeStart - 60)) - int(math.Floor(math.Pow(rng.Float64(), 2)*165))
	var minorValue int = int(timeDiff / 57)
	return "8." + strconv.Itoa(minorValue) + ".0"
}

func firefoxVersion(rng *rand.Rand, now time.Time) int {
	var timeCurrent int64 = now.Unix() / 86400
	var timeStart int64 = time.Date(2024, 7, 29, 0, 0, 0, 0, time.UTC).Unix() / 86400
	var timeDiff = timeCurrent - timeStart - 25 - int64(math.Floor(math.Pow(rng.Float64(), 2)*50))
	return int(timeDiff/30) + 128
}

func safariVersion(rng *rand.Rand, now time.Time) string {
	var anchoredTime time.Time = now
	var releaseYear int = anchoredTime.Year()
	var splitPoint time.Time = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC)
	var delayedDays = int(math.Floor(math.Pow(rng.Float64(), 3) * 75))
	splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	if anchoredTime.Compare(splitPoint) < 0 {
		releaseYear--
		splitPoint = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC)
		splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	}
	var minorVersion = safariMinorMap[(anchoredTime.Unix()-splitPoint.Unix())/1296000]
	return strconv.Itoa(releaseYear-1999) + "." + strconv.Itoa(minorVersion)
}

// ---- Sampling ---------------------------------------------------------------

type versionSet struct {
	curl    string
	firefox string
	safari  string
	chrome  string
}

// drawInstall replays one machine's four draws.
//
// The order is the order Go's package-level initialisers run in, which is
// declaration order among variables whose dependencies are ready: CurlUA,
// AnchoredFirefoxVersion, SafariUA, AnchoredChromeVersion. Reordering these
// would hand each generator another generator's draw.
func drawInstall(rng *rand.Rand, now time.Time) versionSet {
	return versionSet{
		curl:    curlVersion(rng, now),
		firefox: strconv.Itoa(firefoxVersion(rng, now)),
		safari:  safariVersion(rng, now),
		chrome:  strconv.Itoa(chromeVersion(rng, now)),
	}
}

// seedFor rebuilds the FNV-over-CPU-attributes seed of utils.GetRandomizer for
// a synthetic machine.
func seedFor(family, model, physical, logical, cacheLine, threads int) int64 {
	hash := fnv.New64()
	_, _ = hash.Write([]byte(strconv.Itoa(family) + strconv.Itoa(model) + strconv.Itoa(physical) +
		strconv.Itoa(logical) + strconv.Itoa(cacheLine) + strconv.Itoa(threads)))
	return int64(hash.Sum64())
}

// verifyTranscription replays the reference implementation's own seed and clock
// and demands the versions its package init produced. It is what makes the
// transcription above evidence rather than a reading.
func verifyTranscription() error {
	replayed := drawInstall(utils.GetRandomizer(), time.Now())

	safari := utils.SafariUA
	if _, tail, found := strings.Cut(safari, "Version/"); found {
		safari, _, _ = strings.Cut(tail, " Safari/")
	}

	for _, check := range []struct {
		what      string
		ours      string
		reference string
	}{
		{"curl", "curl/" + replayed.curl, utils.CurlUA},
		{"firefox", replayed.firefox, utils.AnchoredFirefoxVersion},
		{"safari", replayed.safari, safari},
		{"chrome", replayed.chrome, strconv.Itoa(utils.AnchoredChromeVersion)},
	} {
		if check.ours != check.reference {
			return fmt.Errorf(
				"%s: transcription says %q, browser.go says %q -- browser.go has changed, or the draw order has",
				check.what, check.ours, check.reference)
		}
	}
	return nil
}

// ---- Output -----------------------------------------------------------------

type share struct {
	Version string  `json:"version"`
	Share   float64 `json:"share"`
}

type distribution struct {
	Unix     int64   `json:"unix"`
	Installs int     `json:"installs"`
	Chrome   []share `json:"chrome"`
	Firefox  []share `json:"firefox"`
	Safari   []share `json:"safari"`
	Curl     []share `json:"curl"`
}

// shares rounds to four decimals, which is finer than the grid's own sampling
// error and coarse enough that the fixture does not churn on noise.
func shares(counts map[string]int, installs int) []share {
	versions := make([]string, 0, len(counts))
	for version := range counts {
		versions = append(versions, version)
	}
	sort.Strings(versions)

	out := make([]share, 0, len(versions))
	for _, version := range versions {
		rounded := math.Round(float64(counts[version])/float64(installs)*10000) / 10000
		out = append(out, share{Version: version, Share: rounded})
	}
	return out
}

func sample() distribution {
	now := time.Unix(fixtureUnix, 0).UTC()
	chrome := map[string]int{}
	firefox := map[string]int{}
	safari := map[string]int{}
	curl := map[string]int{}
	installs := 0

	for family := familyLow; family < familyHigh; family++ {
		for model := modelLow; model < modelHigh; model++ {
			for physical := physicalLow; physical < physicalHigh; physical++ {
				for _, threads := range []int{1, 2} {
					seed := seedFor(family, model, physical, physical*threads, 64, threads)
					drawn := drawInstall(rand.New(rand.NewSource(seed)), now)
					chrome[drawn.chrome]++
					firefox[drawn.firefox]++
					safari[drawn.safari]++
					curl[drawn.curl]++
					installs++
				}
			}
		}
	}

	return distribution{
		Unix:     fixtureUnix,
		Installs: installs,
		Chrome:   shares(chrome, installs),
		Firefox:  shares(firefox, installs),
		Safari:   shares(safari, installs),
		Curl:     shares(curl, installs),
	}
}

func main() {
	checkPath := flag.String("check", "", "compare the generated distribution with a committed JSON file")
	flag.Parse()

	if err := verifyTranscription(); err != nil {
		fmt.Fprintf(os.Stderr, "verify transcription: %v\n", err)
		os.Exit(1)
	}

	generated, err := json.MarshalIndent(sample(), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal distribution: %v\n", err)
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
