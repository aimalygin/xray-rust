mod stream_http_headers_tests {
    use xray_transport::stream::{
        apply_masquerade, apply_masquerade_with_versions, serialize_request, BrowserVersions,
        HeaderMap,
    };

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
        let at = |unix: i64| BrowserVersions::at(unix);

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
        let epoch = BrowserVersions::at(0);

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
            BrowserVersions::at(1_768_262_400).chrome,
            144,
            "2026-01-13, the stated Chrome 144 release date"
        );
    }

    #[test]
    fn the_anchored_versions_are_never_older_than_the_oracles() {
        // Xray subtracts a random number of days from the calendar; we subtract
        // none. Our version can therefore be newer than the fixture's, never
        // older, and it must keep moving as the fixture ages.
        let fixture = decode(CHROME_WS_FIXTURE);
        let anchored = BrowserVersions::anchored();

        assert!(
            anchored.chrome >= fixture.versions.chrome,
            "anchored Chrome {} is older than the oracle's {}",
            anchored.chrome,
            fixture.versions.chrome
        );
        assert!(
            anchored.firefox >= fixture.versions.firefox,
            "anchored Firefox {} is older than the oracle's {}",
            anchored.firefox,
            fixture.versions.firefox
        );
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
