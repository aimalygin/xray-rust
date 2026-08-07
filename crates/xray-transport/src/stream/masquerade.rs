//! Xray's browser-masquerade header block.
//!
//! Ported from `Xray-core/common/utils/browser.go` and verified against the Go
//! oracle in `tools/reality-oracle/masquerade/`, whose fixtures live in
//! `tests/fixtures/masquerade/`. Three rules are easy to invert and all three
//! are load-bearing:
//!
//! 1. An absent `User-Agent` means apply the chrome profile. A `User-Agent`
//!    matching one of the magic keywords means apply that profile. **Any other
//!    value, including the empty string, suppresses the entire block** — so a
//!    user who sets a custom UA silently loses ten other headers.
//! 2. `Sec-CH-UA*`, `DNT`, `User-Agent` and `Accept-Language` overwrite what
//!    the user configured; `Accept`, `Cache-Control` and `Pragma` only fill
//!    gaps.
//! 3. Key casing is literal and non-canonical on purpose (`Sec-CH-UA`, `DNT`),
//!    because Go writes these through the map rather than `Header.Set`.
//!
//! # Where this port deliberately differs
//!
//! Xray derives every browser version from the calendar and then subtracts a
//! random number of days drawn from a PRNG seeded with the host CPU's identity
//! (`GetRandomizer`, `ChromeVersion` in `browser.go`). The draw is fixed per
//! machine, so two Xray installs on different CPUs disagree about today's
//! Chrome version — as of writing, roughly 55% of machines say 148 and the rest
//! say 145 to 147.
//!
//! Reproducing a specific machine's draw would mean porting Go's `math/rand`
//! generator and `klauspost/cpuid`'s per-platform CPU probing, and it would buy
//! nothing: no peer checks our version against what Xray-on-this-CPU would have
//! picked. What matters is that the number keeps moving with the calendar, so
//! it never freezes into a fingerprint of its own.
//!
//! So [`BrowserVersions::at`] ports Xray's date formulas exactly and takes the
//! random term as zero — the single most likely draw (about 10% of machines,
//! against 1% for any other single value) and the newest version Xray's own
//! model allows. We are therefore never older than an Xray client, and at most
//! three Chrome versions newer.
//!
//! One further deviation: Xray's formulas are unbounded below, so a device with
//! a badly wrong clock would announce `Chrome/-441`. Each version is floored at
//! the anchor release its table was written against.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::HeaderMap;

/// The browser versions a masquerade block is built from.
///
/// [`anchored`](Self::anchored) resolves them once per process, the way Go's
/// package-level initialisers do, so every connection from one process claims
/// the same browser. Tests build one from the Go oracle's fixture instead,
/// which is what lets them assert the block byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVersions {
    /// Chrome and Edge major, e.g. `148`.
    pub chrome: u32,
    /// Firefox major, e.g. `151`.
    pub firefox: u32,
    /// Safari `major.minor`, e.g. `"26.6"`.
    pub safari: String,
    /// Full curl version, e.g. `"8.20.0"`.
    pub curl: String,
}

impl BrowserVersions {
    /// The versions this process claims, resolved once on first use.
    pub fn anchored() -> &'static Self {
        static ANCHORED: OnceLock<BrowserVersions> = OnceLock::new();
        ANCHORED.get_or_init(|| Self::at(unix_now()))
    }

    /// The versions Xray's formulas yield at `unix_seconds`, with the random
    /// term at zero. See the module docs.
    pub fn at(unix_seconds: i64) -> Self {
        Self {
            chrome: chrome_version_at(unix_seconds),
            firefox: firefox_version_at(unix_seconds),
            safari: safari_version_at(unix_seconds),
            curl: curl_version_at(unix_seconds),
        }
    }
}

/// Applies the persona Xray would apply for this variant.
///
/// `variant` is `"ws"` for WebSocket and HTTPUpgrade, `"fetch"` for XHTTP and
/// `"nav"` for the REALITY probe. An unknown variant applies the profile
/// headers and nothing else, as Go's `switch` with no matching case does.
pub fn apply_masquerade(headers: &mut HeaderMap, variant: &str) {
    apply_masquerade_with_versions(headers, variant, BrowserVersions::anchored());
}

/// [`apply_masquerade`] against explicit versions.
///
/// Exists so the oracle tests can replay the exact versions a fixture was
/// generated with; production callers want [`apply_masquerade`].
pub fn apply_masquerade_with_versions(
    headers: &mut HeaderMap,
    variant: &str,
    versions: &BrowserVersions,
) {
    let profile = match headers.get("User-Agent") {
        None => Profile::Chrome,
        Some("chrome") => Profile::Chrome,
        Some("firefox") => Profile::Firefox,
        Some("safari") => Profile::Safari,
        Some("edge") => Profile::Edge,
        Some("curl") => Profile::Curl,
        Some("golang") => Profile::Golang,
        Some(_) => return,
    };

    if apply_profile(headers, profile, versions) {
        apply_variant(headers, profile, variant);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Chrome,
    Edge,
    Firefox,
    Safari,
    Curl,
    Golang,
}

/// Writes the browser-specific headers. Returns `false` for the two profiles
/// whose Go arms `return` from `applyMasqueradedHeaders` before the variant
/// switch is reached.
fn apply_profile(headers: &mut HeaderMap, profile: Profile, versions: &BrowserVersions) -> bool {
    match profile {
        Profile::Chrome | Profile::Edge => {
            let brand = if profile == Profile::Chrome {
                "Google Chrome"
            } else {
                "Microsoft Edge"
            };
            headers.set("Sec-CH-UA", &greased_ch_ua(versions.chrome, brand));
            headers.set("Sec-CH-UA-Mobile", "?0");
            headers.set("Sec-CH-UA-Platform", "\"Windows\"");
            headers.set("DNT", "1");
            headers.set("User-Agent", &chromium_user_agent(profile, versions.chrome));
            headers.set("Accept-Language", "en-US,en;q=0.9");
        }
        Profile::Firefox => {
            headers.set("User-Agent", &firefox_user_agent(versions.firefox));
            headers.set("DNT", "1");
            headers.set("Accept-Language", "en-US,en;q=0.5");
        }
        Profile::Safari => {
            headers.set("User-Agent", &safari_user_agent(&versions.safari));
            headers.set("Accept-Language", "en-US,en;q=0.9");
        }
        Profile::Golang => {
            // Xray drops the header so Go's own default UA goes out instead.
            headers.remove("User-Agent");
            return false;
        }
        Profile::Curl => {
            headers.set("User-Agent", &format!("curl/{}", versions.curl));
            return false;
        }
    }
    true
}

fn apply_variant(headers: &mut HeaderMap, profile: Profile, variant: &str) {
    match variant {
        "nav" => {
            if is_blank(headers, "Cache-Control")
                && matches!(profile, Profile::Chrome | Profile::Edge)
            {
                headers.set("Cache-Control", "max-age=0");
            }
            headers.set("Upgrade-Insecure-Requests", "1");
            if is_blank(headers, "Accept") {
                match profile {
                    Profile::Chrome | Profile::Edge => headers.set(
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,\
                         image/avif,image/webp,image/apng,*/*;q=0.8,\
                         application/signed-exchange;v=b3;q=0.7",
                    ),
                    Profile::Firefox | Profile::Safari => headers.set(
                        "Accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ),
                    Profile::Curl | Profile::Golang => {}
                }
            }
            headers.set("Sec-Fetch-Site", "none");
            headers.set("Sec-Fetch-Mode", "navigate");
            if profile != Profile::Safari {
                headers.set("Sec-Fetch-User", "?1");
            }
            headers.set("Sec-Fetch-Dest", "document");
            headers.set("Priority", "u=0, i");
        }
        "ws" => {
            headers.set("Sec-Fetch-Mode", "websocket");
            if profile == Profile::Safari {
                // Safari is NOT web-compliant here!
                headers.set("Sec-Fetch-Dest", "websocket");
            } else {
                headers.set("Sec-Fetch-Dest", "empty");
            }
            headers.set("Sec-Fetch-Site", "same-origin");
            fill_if_blank(headers, "Cache-Control", "no-cache");
            fill_if_blank(headers, "Pragma", "no-cache");
            fill_if_blank(headers, "Accept", "*/*");
        }
        "fetch" => {
            headers.set("Sec-Fetch-Mode", "cors");
            headers.set("Sec-Fetch-Dest", "empty");
            headers.set("Sec-Fetch-Site", "same-origin");
            if is_blank(headers, "Priority") {
                match profile {
                    Profile::Chrome | Profile::Edge => headers.set("Priority", "u=1, i"),
                    Profile::Firefox => headers.set("Priority", "u=4"),
                    Profile::Safari => headers.set("Priority", "u=3, i"),
                    Profile::Curl | Profile::Golang => {}
                }
            }
            fill_if_blank(headers, "Cache-Control", "no-cache");
            fill_if_blank(headers, "Pragma", "no-cache");
            fill_if_blank(headers, "Accept", "*/*");
        }
        _ => {}
    }
}

/// Go's gap-fill test is `header.Get(key) == ""`, which an explicitly empty
/// value satisfies. `HeaderMap::set_if_absent` tests for absence only, so it
/// would leave a bare `Accept:` on the wire where Xray writes `Accept: */*`.
fn is_blank(headers: &HeaderMap, key: &str) -> bool {
    headers.get(key).is_none_or(str::is_empty)
}

fn fill_if_blank(headers: &mut HeaderMap, key: &str, value: &str) {
    if is_blank(headers, key) {
        headers.set(key, value);
    }
}

// ---- User agents ----------------------------------------------------------

fn chromium_user_agent(profile: Profile, chrome: u32) -> String {
    let chrome_ua = format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/{chrome}.0.0.0 Safari/537.36"
    );
    match profile {
        // Xray builds MSEdgeUA by concatenation and forgets the separating
        // space, so the real Edge UA ends `Safari/537.36Edg/148.0.0.0`. Fixing
        // it here would make us the only "Edge" on the internet with the space.
        Profile::Edge => format!("{chrome_ua}Edg/{chrome}.0.0.0"),
        _ => chrome_ua,
    }
}

fn firefox_user_agent(firefox: u32) -> String {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{firefox}.0) Gecko/20100101 \
         Firefox/{firefox}.0"
    )
}

fn safari_user_agent(safari: &str) -> String {
    format!(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) \
         Version/{safari} Safari/605.1.15"
    )
}

// ---- The GREASEd Sec-CH-UA brand list -------------------------------------

const CLIENT_HINT_GREASE_NA: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const CLIENT_HINT_VERSION_NA: [&str; 3] = ["8", "99", "24"];
const CLIENT_HINT_SHUFFLE3: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

/// Chromium's brand GREASE, seeded by the major version, as
/// `getGreasedChUa(major, fork)` does.
///
/// Go's `getGreasedChOrder` also handles brand lists of 1, 2 and 4 entries, but
/// `getUngreasedChUa` only ever produces 3 for the two forks that call it
/// (invalid brand, Chromium, and the fork's own brand), so only the 3-entry
/// shuffle table is ported.
fn greased_ch_ua(major: u32, brand: &str) -> String {
    let seed = major as usize;
    let mut shuffled = vec![String::new(); 3];
    let ungreased = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            CLIENT_HINT_GREASE_NA[seed % CLIENT_HINT_GREASE_NA.len()],
            CLIENT_HINT_GREASE_NA[(seed + 1) % CLIENT_HINT_GREASE_NA.len()],
            CLIENT_HINT_VERSION_NA[seed % CLIENT_HINT_VERSION_NA.len()],
        ),
        format!("\"Chromium\";v=\"{major}\""),
        format!("\"{brand}\";v=\"{major}\""),
    ];

    for (source, &position) in CLIENT_HINT_SHUFFLE3[seed % CLIENT_HINT_SHUFFLE3.len()]
        .iter()
        .enumerate()
    {
        shuffled[position] = ungreased[source].clone();
    }
    shuffled.join(", ")
}

// ---- Version derivation ---------------------------------------------------

/// Chrome 144 was released on 2026-01-13, one release every 35 days.
const CHROME_ANCHOR_VERSION: i64 = 144;
const CHROME_ANCHOR_DAY: i64 = days_from_civil(2026, 1, 13);

/// Firefox 128 ESR, one release every 30 days.
const FIREFOX_ANCHOR_VERSION: i64 = 128;
const FIREFOX_ANCHOR_DAY: i64 = days_from_civil(2024, 7, 29);

/// curl 8.0.0 was released on 2023-03-20; the cadence is 56.67 days, which Xray
/// rounds to 57.
const CURL_ANCHOR_DAY: i64 = days_from_civil(2023, 3, 20);

/// Safari ships a major every 23 September and a minor roughly every 15 days,
/// which Xray tabulates rather than computes.
const SAFARI_MINOR_MAP: [u32; 25] = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
];
const SAFARI_ANCHOR_MAJOR: i64 = 26;

fn chrome_version_at(unix_seconds: i64) -> u32 {
    let elapsed = whole_days(unix_seconds) - CHROME_ANCHOR_DAY - 35;
    (CHROME_ANCHOR_VERSION + elapsed / 35).max(CHROME_ANCHOR_VERSION) as u32
}

fn firefox_version_at(unix_seconds: i64) -> u32 {
    let elapsed = whole_days(unix_seconds) - FIREFOX_ANCHOR_DAY - 25;
    (FIREFOX_ANCHOR_VERSION + elapsed / 30).max(FIREFOX_ANCHOR_VERSION) as u32
}

fn curl_version_at(unix_seconds: i64) -> String {
    let elapsed = whole_days(unix_seconds) - CURL_ANCHOR_DAY - 60;
    format!("8.{}.0", (elapsed / 57).max(0))
}

fn safari_version_at(unix_seconds: i64) -> String {
    // Xray anchors on the previous 23 September when the current year's has not
    // arrived yet, then counts 15-day steps through its minor table.
    let mut release_year = civil_year(whole_days(unix_seconds));
    let mut split = days_from_civil(release_year, 9, 23) * 86_400;
    if unix_seconds < split {
        release_year -= 1;
        split = days_from_civil(release_year, 9, 23) * 86_400;
    }

    let step = ((unix_seconds - split) / 1_296_000).clamp(0, SAFARI_MINOR_MAP.len() as i64 - 1);
    let major = (release_year - 1999).max(SAFARI_ANCHOR_MAJOR);
    format!("{major}.{}", SAFARI_MINOR_MAP[step as usize])
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

/// Whole days since the epoch, as Go's `time.Now().Unix() / 86400`.
///
/// Go truncates toward zero and this floors, which differ by a day for clocks
/// set before 1970 — where the version floors have taken over anyway.
fn whole_days(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(86_400)
}

/// Days from the epoch to a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`). Xray reads calendar dates off `time.Date(.., time.UTC)`;
/// this is the same arithmetic without a calendar dependency.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`], year only.
///
/// Go reads the year off the local clock (`time.Now().Year()`) but builds the
/// 23 September split point in UTC; we use UTC for both, which can disagree
/// with Xray for the few hours a year when the two calendars differ.
fn civil_year(days: i64) -> i64 {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    if month_index >= 10 {
        year + 1
    } else {
        year
    }
}
