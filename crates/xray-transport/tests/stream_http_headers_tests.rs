mod stream_http_headers_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use xray_transport::stream::{
        apply_masquerade, apply_masquerade_with_versions, serialize_request, BrowserVersions,
        HeaderMap, VersionOffsets,
    };

    /// 2026-08-07 00:00:00 UTC. The instant the version-distribution fixture is
    /// frozen at, so the assertions below and the oracle's shares describe the
    /// same day.
    const MEASURED_DAY: i64 = 1_786_060_800;

    /// The entropy the `i`th of `total` evenly spaced draws would carry.
    ///
    /// Sweeping the entropy space rather than sampling it is what lets the
    /// distribution assertions be tight without ever flaking.
    fn swept_entropy(i: u64, total: u64) -> u64 {
        ((u128::from(i) << 64) / u128::from(total)) as u64
    }

    #[test]
    fn host_and_user_agent_lead_then_case_sensitive_key_order() {
        let mut headers = HeaderMap::new();
        headers.set("Upgrade", "websocket");
        headers.set("Sec-Fetch-Mode", "websocket");
        headers.set("Sec-CH-UA-Mobile", "?0");
        headers.set("DNT", "1");
        headers.set("Connection", "Upgrade");
        headers.set("User-Agent", "TestAgent/1.0");

        let request = serialize_request("GET", "/chat", "example.com", &headers);

        assert_eq!(
            String::from_utf8(request).expect("the request must be UTF-8"),
            concat!(
                "GET /chat HTTP/1.1\r\n",
                "Host: example.com\r\n",
                "User-Agent: TestAgent/1.0\r\n",
                "Connection: Upgrade\r\n",
                "DNT: 1\r\n",
                "Sec-CH-UA-Mobile: ?0\r\n",
                "Sec-Fetch-Mode: websocket\r\n",
                "Upgrade: websocket\r\n",
                "\r\n",
            )
        );
    }

    #[test]
    fn key_order_is_case_sensitive_not_alphabetical() {
        // Go compares the literal map keys byte-wise, so every uppercase letter
        // sorts before every lowercase one. A case-insensitive sort would put
        // `Sec-ch-ua` first; Go puts it last.
        let mut headers = HeaderMap::new();
        headers.set("Sec-ch-ua", "lower");
        headers.set("Sec-CH-UA", "upper");

        let request = serialize_request("GET", "/", "h", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");
        let upper = text.find("Sec-CH-UA:").expect("upper key must be present");
        let lower = text.find("Sec-ch-ua:").expect("lower key must be present");

        assert!(upper < lower, "uppercase keys sort first:\n{text}");
    }

    #[test]
    fn a_header_set_twice_keeps_one_value() {
        let mut headers = HeaderMap::new();
        headers.set("X-Thing", "first");
        headers.set("X-Thing", "second");

        let request = serialize_request("GET", "/", "h", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert_eq!(text.matches("X-Thing:").count(), 1, "{text}");
        assert!(text.contains("X-Thing: second"), "{text}");
    }

    #[test]
    fn absent_user_agent_is_not_emitted() {
        let mut headers = HeaderMap::new();
        headers.set("Upgrade", "websocket");

        let request = serialize_request("GET", "/", "example.com", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert!(!text.contains("User-Agent"), "{text}");
        assert!(
            text.starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"),
            "{text}"
        );
    }

    // ---- The browser-masquerade block, against the Go oracle ------------------
    //
    // Regenerate every fixture below with:
    //
    //   go run -C tools/reality-oracle/masquerade \
    //     -tags reality_oracle_masquerade_headers . -variant ws [-user-agent NAME] \
    //     > tests/fixtures/masquerade/headers_NAME_VARIANT.json

    const CHROME_WS_FIXTURE: &str =
        include_str!("../../../tests/fixtures/masquerade/headers_chrome_ws.json");

    const ORACLE_FIXTURES: &[&str] = &[
        CHROME_WS_FIXTURE,
        include_str!("../../../tests/fixtures/masquerade/headers_firefox_ws.json"),
        include_str!("../../../tests/fixtures/masquerade/headers_safari_ws.json"),
        include_str!("../../../tests/fixtures/masquerade/headers_edge_ws.json"),
        include_str!("../../../tests/fixtures/masquerade/headers_curl_ws.json"),
        include_str!("../../../tests/fixtures/masquerade/headers_golang_ws.json"),
        include_str!("../../../tests/fixtures/masquerade/headers_chrome_fetch.json"),
        include_str!("../../../tests/fixtures/masquerade/headers_chrome_nav.json"),
    ];

    #[derive(serde::Deserialize)]
    struct MasqueradeFixture {
        variant: String,
        user_agent: String,
        versions: FixtureVersions,
        headers: Vec<FixtureHeader>,
    }

    /// The versions the oracle run happened to anchor on. Xray derives them from
    /// the date, offset by a draw from a CPU-seeded PRNG, so they are a property
    /// of the machine and day that generated the fixture. Feeding them back in
    /// is what lets these assertions be exact.
    #[derive(serde::Deserialize)]
    struct FixtureVersions {
        chrome: u32,
        firefox: u32,
        safari: String,
        curl: String,
    }

    #[derive(serde::Deserialize)]
    struct FixtureHeader {
        key: String,
        value: String,
    }

    fn decode(fixture: &str) -> MasqueradeFixture {
        serde_json::from_str(fixture).expect("the fixture must decode")
    }

    fn oracle_versions(fixture: &MasqueradeFixture) -> BrowserVersions {
        BrowserVersions {
            chrome: fixture.versions.chrome,
            firefox: fixture.versions.firefox,
            safari: fixture.versions.safari.clone(),
            curl: fixture.versions.curl.clone(),
        }
    }

    fn masqueraded(fixture: &MasqueradeFixture) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if !fixture.user_agent.is_empty() {
            headers.set("User-Agent", &fixture.user_agent);
        }
        apply_masquerade_with_versions(&mut headers, &fixture.variant, &oracle_versions(fixture));
        headers
    }

    /// The request Go would write for this fixture: `Host`, then `User-Agent`,
    /// then every other key in the oracle's byte-wise order. Comparing whole
    /// requests, rather than looking headers up one at a time, is what catches a
    /// header we emit that Xray does not.
    fn oracle_request(fixture: &MasqueradeFixture) -> String {
        let mut out = String::from("GET /path HTTP/1.1\r\nHost: oracle.example\r\n");
        for header in fixture.headers.iter().filter(|h| h.key == "User-Agent") {
            out.push_str(&format!("{}: {}\r\n", header.key, header.value));
        }
        for header in fixture.headers.iter().filter(|h| h.key != "User-Agent") {
            out.push_str(&format!("{}: {}\r\n", header.key, header.value));
        }
        out.push_str("\r\n");
        out
    }

    #[test]
    fn the_chrome_ws_block_matches_the_go_oracle() {
        let fixture = decode(CHROME_WS_FIXTURE);
        let headers = masqueraded(&fixture);

        for expected in &fixture.headers {
            assert_eq!(
                headers.get(&expected.key),
                Some(expected.value.as_str()),
                "header {} must match the oracle",
                expected.key
            );
        }
    }

    #[test]
    fn every_oracle_fixture_matches_header_for_header() {
        for raw in ORACLE_FIXTURES {
            let fixture = decode(raw);
            let headers = masqueraded(&fixture);
            let request = serialize_request("GET", "/path", "oracle.example", &headers);

            assert_eq!(
                String::from_utf8(request).expect("the request must be UTF-8"),
                oracle_request(&fixture),
                "profile {:?} variant {:?} must match the oracle exactly",
                fixture.user_agent,
                fixture.variant
            );
        }
    }

    #[test]
    fn a_real_user_agent_suppresses_the_whole_block() {
        // Xray applies nothing when the configured UA is not one of its magic
        // keywords, so "I set a custom UA" silently drops ~10 other headers.
        let mut headers = HeaderMap::new();
        headers.set("User-Agent", "MyClient/2.0");
        apply_masquerade(&mut headers, "ws");

        assert_eq!(headers.get("User-Agent"), Some("MyClient/2.0"));
        assert_eq!(headers.get("Sec-Fetch-Mode"), None);
        assert_eq!(headers.get("DNT"), None);
    }

    #[test]
    fn an_empty_user_agent_also_suppresses_the_whole_block() {
        // Go tests `len(header.Values("User-Agent")) < 1`, not emptiness, so a
        // configured `"User-Agent": ""` is present-but-unrecognized: no profile.
        let mut headers = HeaderMap::new();
        headers.set("User-Agent", "");
        apply_masquerade(&mut headers, "ws");

        assert_eq!(headers.get("User-Agent"), Some(""));
        assert_eq!(headers.get("Sec-Fetch-Mode"), None);
    }

    #[test]
    fn accept_is_filled_only_when_absent_while_dnt_overrides() {
        let mut headers = HeaderMap::new();
        headers.set("Accept", "text/plain");
        headers.set("DNT", "0");
        apply_masquerade(&mut headers, "ws");

        assert_eq!(
            headers.get("Accept"),
            Some("text/plain"),
            "Accept only fills gaps"
        );
        assert_eq!(headers.get("DNT"), Some("1"), "DNT is overwritten");
    }

    #[test]
    fn an_empty_gap_filled_header_counts_as_absent() {
        // The gap-fill test in Go is `header.Get("Accept") == ""`, which an
        // explicitly empty value satisfies. Treating it as present would put a
        // bare `Accept:` on the wire, which no browser sends.
        let mut headers = HeaderMap::new();
        headers.set("Accept", "");
        headers.set("Cache-Control", "");
        headers.set("Pragma", "");
        apply_masquerade(&mut headers, "ws");

        assert_eq!(headers.get("Accept"), Some("*/*"));
        assert_eq!(headers.get("Cache-Control"), Some("no-cache"));
        assert_eq!(headers.get("Pragma"), Some("no-cache"));
    }

    #[test]
    fn the_release_calendar_drives_the_versions() {
        // Xray's own formulas with the PRNG term at zero. The Chrome anchor is
        // 144 on 2026-01-13, but the formula subtracts 35 days before dividing,
        // so it does not actually reach 144 until 2026-02-17.
        let at = |unix: i64| BrowserVersions::at(unix, &VersionOffsets::NONE);

        assert_eq!(
            at(1_771_286_400).chrome,
            144,
            "2026-02-17, anchor + 35 days"
        );
        assert_eq!(
            at(1_774_224_000).chrome,
            144,
            "2026-03-23, anchor + 69 days"
        );
        assert_eq!(
            at(1_774_310_400).chrome,
            145,
            "2026-03-24, anchor + 70 days"
        );
        assert_eq!(at(1_798_761_600).chrome, 153, "2027-01-01");

        assert_eq!(at(1_786_060_800).firefox, 151, "2026-08-07");
        assert_eq!(at(1_798_761_600).firefox, 156, "2027-01-01");

        assert_eq!(at(1_786_060_800).curl, "8.20.0", "2026-08-07");
        assert_eq!(at(1_798_761_600).curl, "8.23.0", "2027-01-01");

        // Safari rolls its major over on 23 September, and its minor every 15
        // days from there.
        assert_eq!(at(1_790_035_200).safari, "26.6", "2026-09-22");
        assert_eq!(at(1_790_121_600).safari, "27.0", "2026-09-23");
        assert_eq!(at(1_798_761_600).safari, "27.2", "2027-01-01");
    }

    #[test]
    fn a_wrong_clock_falls_back_to_the_anchor_releases() {
        // Xray's formulas are unbounded below: at the Unix epoch they yield
        // Chrome/-441 and curl/8.-342.0, which is a louder fingerprint than any
        // stale version. A phone with a dead RTC really does boot in 1970.
        let epoch = BrowserVersions::at(0, &VersionOffsets::NONE);

        assert_eq!(epoch.chrome, 144);
        assert_eq!(epoch.firefox, 128);
        assert_eq!(epoch.curl, "8.0.0");
        assert!(
            epoch.safari.starts_with("26."),
            "Safari fell back to {}",
            epoch.safari
        );

        // The floor holds right up to the anchor date, where Xray itself would
        // still say 143: the formula subtracts 35 days before dividing.
        assert_eq!(
            BrowserVersions::at(1_768_262_400, &VersionOffsets::NONE).chrome,
            144,
            "2026-01-13, the stated Chrome 144 release date"
        );
    }

    /// One of Xray's four offset curves: its name, the field it lands in, and
    /// the `span` and `power` of `floor(U^power * span)`.
    type OffsetDomain = (&'static str, fn(&VersionOffsets) -> i64, i64, f64);

    #[test]
    fn the_offset_draw_reproduces_xrays_distribution() {
        // Xray subtracts `floor(U^power * span)` days from the calendar, U
        // uniform on [0, 1), so the chance of an offset of at most k is
        // ((k+1)/span)^(1/power). Reproducing that curve is the whole
        // requirement: nothing checks our draw against what Xray-on-this-CPU
        // would have picked, only that our population spreads the way theirs
        // does.
        const SAMPLES: u64 = 200_000;

        let domains: [OffsetDomain; 4] = [
            ("chrome", |o| o.chrome_days, 105, 2.0),
            ("firefox", |o| o.firefox_days, 50, 2.0),
            ("curl", |o| o.curl_days, 165, 2.0),
            ("safari", |o| o.safari_days, 75, 3.0),
        ];

        for (name, offset_of, span, power) in domains {
            let mut histogram = vec![0u64; span as usize];
            for i in 0..SAMPLES {
                let entropy = swept_entropy(i, SAMPLES);
                let offset = offset_of(&VersionOffsets::from_entropy([entropy; 4]));
                assert!(
                    (0..span).contains(&offset),
                    "{name} drew {offset}, outside 0..{span}"
                );
                histogram[offset as usize] += 1;
            }

            assert_eq!(
                offset_of(&VersionOffsets::from_entropy([u64::MAX; 4])),
                span - 1,
                "{name}: the largest word of entropy must land inside the span, \
                 not one past it"
            );

            let mut seen = 0u64;
            for (days, count) in histogram.iter().enumerate() {
                seen += count;
                let ours = seen as f64 / SAMPLES as f64;
                let xrays = ((days + 1) as f64 / span as f64).powf(1.0 / power);
                assert!(
                    (ours - xrays).abs() < 1e-3,
                    "{name}: we put {ours} of installs at an offset of at most \
                     {days} days, Xray puts {xrays}"
                );
            }
        }
    }

    /// Regenerate with:
    ///
    ///   go run -C tools/reality-oracle/masquerade \
    ///     -tags reality_oracle_version_distribution . \
    ///     > tests/fixtures/masquerade/version_distribution.json
    const VERSION_DISTRIBUTION_FIXTURE: &str =
        include_str!("../../../tests/fixtures/masquerade/version_distribution.json");

    #[derive(serde::Deserialize)]
    struct VersionDistribution {
        unix: i64,
        chrome: Vec<VersionShare>,
        firefox: Vec<VersionShare>,
        safari: Vec<VersionShare>,
        curl: Vec<VersionShare>,
    }

    #[derive(serde::Deserialize)]
    struct VersionShare {
        version: String,
        share: f64,
    }

    #[test]
    fn the_drawn_versions_spread_the_way_xray_installs_do() {
        // The oracle runs Xray's own generators over 25 600 synthetic CPU
        // identities; we sweep our entropy space at the same instant. Neither
        // side can reproduce the other's individual draw -- ours comes from the
        // OS CSPRNG, Xray's from the host CPU -- so matching the population is
        // the whole of what we owe them, and the only thing an observer
        // aggregating across installs can see.
        const SAMPLES: u64 = 200_000;
        // The oracle's grid samples the curve where our sweep is its exact
        // limit, so the two disagree by up to about 0.004.
        const TOLERANCE: f64 = 0.01;

        let oracle: VersionDistribution =
            serde_json::from_str(VERSION_DISTRIBUTION_FIXTURE).expect("the fixture must decode");

        let mut ours: [BTreeMap<String, u64>; 4] = std::array::from_fn(|_| BTreeMap::new());
        for i in 0..SAMPLES {
            let offsets = VersionOffsets::from_entropy([swept_entropy(i, SAMPLES); 4]);
            let versions = BrowserVersions::at(oracle.unix, &offsets);
            let reported = [
                versions.chrome.to_string(),
                versions.firefox.to_string(),
                versions.safari,
                versions.curl,
            ];
            for (counts, version) in ours.iter_mut().zip(reported) {
                *counts.entry(version).or_default() += 1;
            }
        }

        for (browser, xrays, ours) in [
            ("chrome", &oracle.chrome, &ours[0]),
            ("firefox", &oracle.firefox, &ours[1]),
            ("safari", &oracle.safari, &ours[2]),
            ("curl", &oracle.curl, &ours[3]),
        ] {
            let reached: BTreeSet<&str> = ours.keys().map(String::as_str).collect();
            let xray_reaches: BTreeSet<&str> =
                xrays.iter().map(|entry| entry.version.as_str()).collect();
            assert_eq!(
                reached, xray_reaches,
                "{browser}: our installs reach a different set of versions than Xray's"
            );

            for entry in xrays {
                let ours = ours[&entry.version] as f64 / SAMPLES as f64;
                assert!(
                    (ours - entry.share).abs() < TOLERANCE,
                    "{browser} {}: {ours} of our installs report it, against Xray's {}",
                    entry.version,
                    entry.share
                );
            }
        }
    }

    #[test]
    fn a_delayed_safari_split_point_holds_the_older_version() {
        // Safari is the one generator whose draw delays the 23 September
        // rollover rather than subtracting from the elapsed time. The effect is
        // the same direction -- an older version -- but it reaches the major,
        // not just the minor.
        let delayed = |days| VersionOffsets {
            safari_days: days,
            ..VersionOffsets::NONE
        };

        // 2026-08-07 sits 318 days past the 2025 split point: 21 fifteen-day
        // steps in with no delay, 16 with the largest one.
        assert_eq!(
            BrowserVersions::at(MEASURED_DAY, &VersionOffsets::NONE).safari,
            "26.6"
        );
        assert_eq!(
            BrowserVersions::at(MEASURED_DAY, &delayed(74)).safari,
            "26.5"
        );

        // On rollover day itself, one delayed day is enough to keep the
        // previous major for another year.
        let rollover = 1_790_121_600; // 2026-09-23
        assert_eq!(
            BrowserVersions::at(rollover, &VersionOffsets::NONE).safari,
            "27.0"
        );
        assert_eq!(BrowserVersions::at(rollover, &delayed(1)).safari, "26.6");
    }

    #[test]
    fn every_drawn_version_is_one_xrays_model_can_produce() {
        // The OS CSPRNG path has to agree with the pure one it is documented
        // against. The offset domain is small enough to enumerate, so the set
        // of reachable versions is exact rather than sampled.
        let reachable: BTreeSet<u32> = (0..105)
            .map(|days| {
                let offsets = VersionOffsets {
                    chrome_days: days,
                    ..VersionOffsets::NONE
                };
                BrowserVersions::at(MEASURED_DAY, &offsets).chrome
            })
            .collect();

        for _ in 0..200 {
            let drawn = BrowserVersions::at(MEASURED_DAY, &VersionOffsets::drawn()).chrome;
            assert!(
                reachable.contains(&drawn),
                "drew Chrome {drawn}, which is outside {reachable:?}"
            );
        }
    }

    #[test]
    fn separate_draws_disagree() {
        // The point of the whole exercise: two installs must not report the
        // same browser. Repeated draws stand in for separate processes, the way
        // the fingerprint draw is sampled.
        let mut drawn = BTreeSet::new();
        for _ in 0..200 {
            drawn.insert(BrowserVersions::at(MEASURED_DAY, &VersionOffsets::drawn()).chrome);
        }

        assert!(drawn.len() > 1, "200 draws all reported {drawn:?}");
    }

    #[test]
    fn the_anchored_versions_stay_fixed_for_the_whole_process() {
        // And the other half of it: a client whose User-Agent moves between
        // connections is easier to pick out than one that never moves, so the
        // draw is made once and pinned.
        assert_eq!(BrowserVersions::anchored(), BrowserVersions::anchored());

        let user_agent = || {
            let mut headers = HeaderMap::new();
            apply_masquerade(&mut headers, "ws");
            headers
                .get("User-Agent")
                .expect("the chrome profile sets a User-Agent")
                .to_owned()
        };

        assert_eq!(user_agent(), user_agent());
    }

    #[test]
    fn a_host_entry_in_the_map_does_not_duplicate_the_host_line() {
        // Go writes Host from Request.Host, not the header map, and excludes it
        // from the sorted remainder. Two Host lines would be an RFC 7230 §5.4
        // violation most servers reject.
        let mut headers = HeaderMap::new();
        headers.set("Host", "attacker.example");

        let request = serialize_request("GET", "/", "example.com", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert_eq!(text.matches("Host:").count(), 1, "{text}");
        assert!(text.contains("Host: example.com"), "{text}");
    }
}
