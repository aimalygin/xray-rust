const coreUrl = "https://github.com/aimalygin/xray-rust";
const mobileUrl = "https://github.com/aimalygin/xray-rust-mobile";
const kmpUrl = "https://github.com/aimalygin/xray-rust-kmp";
const releaseVersion = "0.10.1";
const kmpTagUrl = `${kmpUrl}/tree/v0.10.1`;
const releaseUrl = `${coreUrl}/releases/tag/v${releaseVersion}`;
const compatibilityUrl = `${coreUrl}/blob/v${releaseVersion}/docs/config-compatibility.md`;
const benchmarkUrl = `${coreUrl}/blob/v0.9.0/docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/README.md`;

const features = [
  {
    number: "01",
    title: "VLESS, REALITY, Vision",
    body: "VLESS with shaped TLS and REALITY ClientHellos, Vision, UDP, XUDP and Mux. RAW, WebSocket, HTTPUpgrade, gRPC and XHTTP transports cover a documented configuration subset.",
  },
  {
    number: "02",
    title: "More client protocols",
    body: "Choose from VMess AEAD, Trojan, Shadowsocks 2022 and classic AEAD, Hysteria 2, WireGuard, MASQUE, SOCKS5 and HTTP CONNECT.",
  },
  {
    number: "03",
    title: "Native tunnel adapters",
    body: "Apple Network Extension and Android VpnService adapters, with packet and file-descriptor TUN paths. SwiftPM, a static XCFramework and a four-ABI Android AAR.",
  },
  {
    number: "04",
    title: "Routing and encrypted DNS",
    body: "Field rules, geosite and geoip, health-aware selectors, hot-swappable routing policy, DoT, DoH, local DoQ, TTL-aware caching and fake IP mapping.",
  },
  {
    number: "05",
    title: "Profiles and live diagnostics",
    body: "Swift and Kotlin profile import, capability discovery, live connection inventory and traffic counters. Probe outbounds on demand and cancel probes already in flight.",
  },
  {
    number: "06",
    title: "Control at tunnel startup",
    body: "Startup-probe preflight on Apple and Android, bounded queues and configurable Hysteria 2 stream limits. Opt-in TUN admission lets the host decide which new flows to accept.",
  },
];

const faqs = [
  {
    question: "What is xray-rust?",
    answer:
      "xray-rust is an embeddable Rust client core for a documented subset of Xray configurations. The mobile SDK packages it for Apple and Android. The Kotlin Multiplatform library adds a shared API for Android and iOS apps.",
  },
  {
    question: "Which client protocols does the core support?",
    answer:
      "VLESS, VMess AEAD, Trojan, Shadowsocks 2022 and classic AEAD, Hysteria 2, WireGuard, MASQUE, SOCKS5 and HTTP/HTTPS CONNECT. The compatibility guide lists the transports and security settings each outbound accepts.",
  },
  {
    question: "Can I use it in an Apple Network Extension?",
    answer:
      "Yes. Add xray-rust-mobile through SwiftPM and subclass the Packet Tunnel provider from XrayAppleTunnel. The SDK supports iOS 15+, tvOS 17+ and macOS 11+. Newer XrayAppleTunnel APIs require macOS 13. Your app supplies signing, entitlements and VPN consent.",
  },
  {
    question: "Is there an Android SDK?",
    answer:
      "Yes. The xray-rust-mobile AAR is on Maven Central. It supports Android API 24+, includes four native ABIs and ships a VpnService adapter. Your app manages VPN consent and foreground-service policy.",
  },
  {
    question: "What can I share between Android and iOS with Kotlin Multiplatform?",
    answer:
      "Shared Kotlin code imports proxy links, starts and stops tunnels, and observes connection state. Android uses the native VpnService adapter. On iOS, Kotlin runs in the app and the Packet Tunnel extension uses Swift. The KMP release has build and simulator coverage. Physical-device testing of the KMP layer is still pending.",
  },
  {
    question: "Do the benchmark numbers describe mobile VPN speed?",
    answer:
      "The table measures localhost processes on an Apple M6 at xray-rust commit 123b9d8d. For mobile tunnel measurements, see the physical-device evidence in the core release notes.",
  },
  {
    question: "Is this project affiliated with XTLS or Xray-core?",
    answer:
      "No. xray-rust is an independent open-source implementation, licensed under MPL-2.0, and is not affiliated with or endorsed by XTLS or Xray-core. It has not been independently security audited.",
  },
];

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareSourceCode",
      name: "xray-rust",
      description:
        "Rust client core with native Apple and Android tunnel adapters and a Kotlin Multiplatform library for Android and iOS.",
      codeRepository: coreUrl,
      version: releaseVersion,
      releaseNotes: releaseUrl,
      programmingLanguage: "Rust",
      license: "https://www.mozilla.org/en-US/MPL/2.0/",
      runtimePlatform: ["iOS", "tvOS", "macOS", "Android"],
    },
    {
      "@type": "FAQPage",
      mainEntity: faqs.map(({ question, answer }) => ({
        "@type": "Question",
        name: question,
        acceptedAnswer: { "@type": "Answer", text: answer },
      })),
    },
  ],
};

export default function Home() {
  return (
    <main id="top">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      <header className="site-header shell">
        <a className="brand" href="#top" aria-label="xray-rust home">
          <span className="brand-mark" aria-hidden="true">xr</span>
          <span>xray-rust</span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="#release">{releaseVersion}</a>
          <a href="#features">Features</a>
          <a href="#performance">Performance</a>
          <a href="#platforms">Platforms</a>
          <a href="#faq">FAQ</a>
          <a href={coreUrl}>GitHub ↗</a>
        </nav>
      </header>

      <section className="hero shell">
        <div className="hero-copy">
          <p className="eyebrow">Open source · MPL-2.0 · Rust</p>
          <a className="release-badge" href="#release">Core + SDK {releaseVersion} <span aria-hidden="true">↗</span></a>
          <h1>A focused Xray client core built for mobile.</h1>
          <p className="lede">
            Bring VLESS, REALITY, Hysteria 2, WireGuard and more to Apple and
            Android apps. Integrate the native SDK or share profile import and
            tunnel control between Android and iOS with Kotlin Multiplatform.
          </p>
          <div className="actions">
            <a className="button primary" href={mobileUrl}>Get the mobile SDK</a>
            <a className="button secondary" href="#kotlin-multiplatform">Use Kotlin Multiplatform</a>
          </div>
          <p className="install-line">
            <span>$</span> SwiftPM · XCFramework · Android AAR
          </p>
        </div>

        <aside className="signal-card" aria-label="Benchmark highlights">
          <div className="signal-topline">
            <span>BENCHMARK / APPLE M6</span>
            <span className="verified">2026-10-30</span>
          </div>
          <div className="metric">
            <strong>4.6</strong>
            <span>MiB idle RSS</span>
          </div>
          <div className="meter" aria-hidden="true"><span /></div>
          <div className="metric-grid">
            <div><strong>22.1</strong><span>Gbps REALITY + Vision</span></div>
            <div><strong>22.7</strong><span>MiB at 1,000 flows</span></div>
          </div>
          <p>Five-run localhost medians at core commit 123b9d8d.</p>
        </aside>
      </section>

      <section className="platform-strip" aria-label="Supported platforms">
        <div className="shell platform-row">
          <span>iOS 15+</span>
          <span>tvOS 17+</span>
          <span>macOS 11+</span>
          <span>Android API 24+</span>
        </div>
      </section>

      <section className="section shell" id="features">
        <div className="section-heading">
          <p className="eyebrow">Core capabilities</p>
          <h2>The client path, without the weight.</h2>
          <p>Client features in {releaseVersion} and the native APIs for host apps.</p>
        </div>
        <div className="feature-grid">
          {features.map((feature) => (
            <article className="feature-card" key={feature.number}>
              <span className="feature-number">{feature.number}</span>
              <h3>{feature.title}</h3>
              <p>{feature.body}</p>
            </article>
          ))}
        </div>
        <p className="section-note">Every protocol supports a documented subset. <a href={compatibilityUrl}>Read the {releaseVersion} compatibility guide ↗</a></p>
      </section>

      <section className="section performance-section" id="performance">
        <div className="shell">
          <div className="section-heading performance-heading">
            <div>
              <p className="eyebrow">Published benchmark · 30 October 2026</p>
              <h2>Small footprint. Competitive throughput.</h2>
            </div>
            <a className="text-link" href={benchmarkUrl}>Read the methodology ↗</a>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th scope="col">Apple M6 / localhost</th><th scope="col">xray-rust<br />123b9d8d</th><th scope="col">Xray-core<br />v26.10.21</th><th scope="col">sing-box<br />v1.14.4</th></tr>
              </thead>
              <tbody>
                <tr><td>Idle RSS <span>lower is better</span></td><td className="winner">4.6 MiB</td><td>27.4 MiB</td><td>30.8 MiB</td></tr>
                <tr><td>1,000 held flows <span>lower is better</span></td><td className="winner">22.7 MiB</td><td>78.6 MiB</td><td>Omitted¹</td></tr>
                <tr><td>REALITY + Vision bulk <span>higher is better</span></td><td className="winner">22.1 Gbps</td><td>19.1 Gbps</td><td>Omitted²</td></tr>
              </tbody>
            </table>
          </div>
          <p className="benchmark-note">Five-run medians on an Apple M6 MacBook, 32 GB RAM, macOS 27.0. The client and server ran on the same machine. RSS is peak resident memory.</p>
          <p className="benchmark-note">¹ sing-box’s 1,000-flow runs failed during connection setup. ² Its REALITY client was incompatible with the tested server’s ML-KEM requirement. The report preserves these omissions, raw results and exact source identities.</p>
        </div>
      </section>

      <section className="section shell" id="platforms">
        <div className="section-heading platform-heading">
          <p className="eyebrow">SDK integration</p>
          <h2>Choose an SDK for your app.</h2>
          <p>Mobile SDK {releaseVersion} packages core v{releaseVersion} with C ABI 1.17. The KMP library wraps those same native adapters.</p>
        </div>
        <div className="sdk-grid">
          <article className="sdk-card">
            <div className="sdk-title"><span className="platform-icon">A</span><div><p>Apple platforms</p><h3>Network Extension adapter</h3></div></div>
            <p className="sdk-note">Pin xray-rust-mobile to {releaseVersion} in Swift Package Manager.</p>
            <pre><code><span>import</span> XrayAppleTunnel{"\n\n"}<span>final class</span> PacketTunnelProvider:{"\n    "}XrayPacketTunnelProvider {"{}"}</code></pre>
            <a className="text-link" href={`${mobileUrl}#apple-platforms-with-swift-package-manager`}>Apple setup guide ↗</a>
            <p className="sdk-note">iOS 15+ · tvOS 17+ · macOS 11+ for the core SDK; newer XrayAppleTunnel APIs require macOS 13.</p>
          </article>
          <article className="sdk-card">
            <div className="sdk-title"><span className="platform-icon android">A</span><div><p>Android</p><h3>VpnService adapter</h3></div></div>
            <p className="sdk-note">Add mavenCentral() to your Gradle repositories.</p>
            <pre><code>dependencies {" {\n    "}implementation({"\n        "}<span>&quot;io.github.aimalygin:xray-rust-mobile:{releaseVersion}&quot;</span>{"\n    "}){"\n}"}</code></pre>
            <a className="text-link" href={`${mobileUrl}#android-with-gradle`}>Android setup guide ↗</a>
          </article>
          <article className="sdk-card kmp-card" id="kotlin-multiplatform">
            <div className="sdk-title"><span className="platform-icon" aria-hidden="true">K</span><div><p>Shared Android and iOS code</p><h3>Kotlin Multiplatform</h3></div></div>
            <p>Use <code>XrayProfiles</code> to import a proxy link and <code>XrayTunnel</code> to start, stop and observe the VPN from shared Kotlin code. The iOS Packet Tunnel extension stays in Swift.</p>
            <p>Check out tag <code>v0.10.1</code> of <a href={kmpUrl}>xray-rust-kmp</a> and include it in Gradle as a composite build. Maven Central supplies the underlying Android AAR. On iOS, also pin the native Swift package to <code>0.10.1</code>.</p>
            <a className="text-link" href={`${kmpTagUrl}#use-it-in-your-project`}>KMP setup guide</a>
          </article>
        </div>
      </section>

      <section className="section release-section" id="release">
        <div className="shell release-grid">
          <div>
            <p className="eyebrow">Core release · 18 November 2026</p>
            <h2>What’s new in {releaseVersion}.</h2>
            <p className="section-note">Core + mobile SDK · C ABI 1.17<br />Compatibility reference: Xray-core v26.11.9</p>
          </div>
          <div className="release-copy">
            <ul className="release-changes">
              <li><strong>QUIC and TLS.</strong> The release updates Quinn and rustls with upstream security fixes. TLS and REALITY fingerprints now advertise the full cipher suite list for their uTLS profile.</li>
              <li><strong>Tunnel lifecycle.</strong> Hysteria gives the final server address more time to connect. Shutting down the core can now finish while a system DNS lookup is still in progress.</li>
              <li><strong>Kotlin Multiplatform.</strong> The matching <a className="text-link" href={`${kmpUrl}/releases/tag/v0.10.1`}>KMP source release</a> targets the same native SDK and C ABI.</li>
            </ul>
            <p className="release-evidence">Core validation included physical iPhone and Samsung runs. Nine protocols exceeded the peak-memory budget against 0.9.0. The release notes detail the device coverage and known limits.</p>
            <div className="release-points"><span>✓ Pinned core revision</span><span>✓ SHA-256 checksums</span><span>✓ Reproducible metadata</span></div>
            <div className="actions">
              <a className="button secondary" href={releaseUrl}>Release notes &amp; evidence ↗</a>
              <a className="button secondary" href={`${mobileUrl}/releases/tag/v${releaseVersion}`}>SDK {releaseVersion} downloads ↗</a>
            </div>
          </div>
        </div>
      </section>

      <section className="section shell faq-section" id="faq">
        <div className="section-heading">
          <p className="eyebrow">FAQ</p>
          <h2>Useful answers, up front.</h2>
        </div>
        <div className="faq-list">
          {faqs.map((faq) => (
            <details key={faq.question}>
              <summary>{faq.question}<span aria-hidden="true">+</span></summary>
              <p>{faq.answer}</p>
            </details>
          ))}
        </div>
      </section>

      <section className="cta shell">
        <p className="eyebrow">Build with xray-rust</p>
        <h2>Start with the core.<br />Ship with the mobile SDK.</h2>
        <div className="actions centered">
          <a className="button primary" href={coreUrl}>View on GitHub</a>
          <a className="button secondary" href={mobileUrl}>Mobile integration</a>
        </div>
      </section>

      <footer className="site-footer shell">
        <a className="brand" href="#top"><span className="brand-mark" aria-hidden="true">xr</span><span>xray-rust</span></a>
        <p>Independent open-source software, licensed under MPL-2.0. Not affiliated with or endorsed by XTLS or Xray-core.</p>
        <div><a href={coreUrl}>Core</a><a href={mobileUrl}>Mobile</a><a href={kmpUrl}>KMP</a><a href={`${coreUrl}/blob/main/LICENSE`}>License</a></div>
      </footer>
    </main>
  );
}
