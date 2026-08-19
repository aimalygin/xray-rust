const coreUrl = "https://github.com/aimalygin/xray-rust";
const mobileUrl = "https://github.com/aimalygin/xray-rust-mobile";
const benchmarkUrl = `${coreUrl}/blob/main/docs/benchmarks/results.md`;

const features = [
  {
    number: "01",
    title: "VLESS, REALITY, Vision",
    body: "A focused Xray-compatible client path, including TLS and REALITY with shaped ClientHellos, Vision flow, UDP, and XUDP.",
  },
  {
    number: "02",
    title: "Mobile TUN integration",
    body: "Native adapters for Apple Network Extension and Android VpnService, packaged for SwiftPM, XCFramework, and AAR consumers.",
  },
  {
    number: "03",
    title: "Routing and DNS",
    body: "Field rules, geosite and geoip matching, multi-address resolution, TTL-aware caching, fake IP mapping, and shared outbound policy.",
  },
];

const faqs = [
  {
    question: "What is xray-rust?",
    answer:
      "xray-rust is an open-source, embeddable Rust client core for the documented Xray configuration subset used by mobile proxy and VPN clients.",
  },
  {
    question: "Does it support VLESS, REALITY, and Vision?",
    answer:
      "Yes. The supported client path includes VLESS over TCP, TLS or REALITY, xtls-rprx-vision flow, UDP, and XUDP. The repository documents the exact compatibility boundary.",
  },
  {
    question: "Can I use it in an iOS Network Extension?",
    answer:
      "Yes. xray-rust-mobile provides an Apple adapter built around NetworkExtension, with SwiftPM and prebuilt XCFramework distribution options.",
  },
  {
    question: "Is there an Android SDK?",
    answer:
      "Yes. The Android adapter targets VpnService and is published as an AAR through GitHub Packages, with reproducible release metadata in the repository.",
  },
  {
    question: "Is this project affiliated with XTLS or Xray-core?",
    answer:
      "No. xray-rust is an independent open-source implementation and is not affiliated with or endorsed by the XTLS or Xray-core projects.",
  },
];

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareSourceCode",
      name: "xray-rust",
      description:
        "An embeddable Rust client core for VLESS, REALITY, Vision, TUN, routing, and DNS, with native Apple and Android SDK packages.",
      codeRepository: coreUrl,
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
          <h1>A focused Xray client core built for mobile.</h1>
          <p className="lede">
            Embed VLESS, REALITY, Vision, TUN, routing, and DNS in Apple and
            Android apps—with native adapters and reproducible binary releases.
          </p>
          <div className="actions">
            <a className="button primary" href={mobileUrl}>Get the mobile SDK</a>
            <a className="button secondary" href={coreUrl}>Explore the core</a>
          </div>
          <p className="install-line">
            <span>$</span> SwiftPM · XCFramework · Android AAR
          </p>
        </div>

        <aside className="signal-card" aria-label="Benchmark highlights">
          <div className="signal-topline">
            <span>BENCHMARK / APPLE M3 PRO</span>
            <span className="verified">VERIFIED</span>
          </div>
          <div className="metric">
            <strong>3.84</strong>
            <span>MiB idle RSS</span>
          </div>
          <div className="meter" aria-hidden="true"><span /></div>
          <div className="metric-grid">
            <div><strong>14.3</strong><span>Gbps REALITY + Vision</span></div>
            <div><strong>18.3</strong><span>MiB at 1,000 flows</span></div>
          </div>
          <p>Synthetic localhost benchmark. Methodology and raw results are public.</p>
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
          <p>A deliberately scoped implementation for teams embedding modern Xray transport in native apps.</p>
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
      </section>

      <section className="section performance-section" id="performance">
        <div className="shell">
          <div className="section-heading performance-heading">
            <div>
              <p className="eyebrow">Published benchmark</p>
              <h2>Small footprint. Competitive throughput.</h2>
            </div>
            <a className="text-link" href={benchmarkUrl}>Read the methodology ↗</a>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Apple M3 Pro / localhost</th><th>xray-rust</th><th>Xray-core</th><th>sing-box</th></tr>
              </thead>
              <tbody>
                <tr><td>Idle RSS <span>lower is better</span></td><td className="winner">3.84 MiB</td><td>28.1 MiB</td><td>20.9 MiB</td></tr>
                <tr><td>1,000 held flows <span>lower is better</span></td><td className="winner">18.3 MiB</td><td>79.9 MiB</td><td>46.1 MiB</td></tr>
                <tr><td>REALITY + Vision bulk <span>higher is better</span></td><td className="winner">14.3 Gbps</td><td>13.7 Gbps</td><td>14.0 Gbps</td></tr>
              </tbody>
            </table>
          </div>
          <p className="benchmark-note">Synthetic process-level results are workload- and machine-specific. Commands, inputs, and raw output are published for reproduction.</p>
        </div>
      </section>

      <section className="section shell" id="platforms">
        <div className="section-heading platform-heading">
          <p className="eyebrow">Native distribution</p>
          <h2>One Rust core. Two mobile ecosystems.</h2>
          <p>Use source packages during development or pin a verified binary release in production.</p>
        </div>
        <div className="sdk-grid">
          <article className="sdk-card">
            <div className="sdk-title"><span className="platform-icon">A</span><div><p>Apple platforms</p><h3>Network Extension adapter</h3></div></div>
            <pre><code><span>import</span> XrayAppleTunnel{"\n\n"}<span>final class</span> PacketTunnelProvider:{"\n    "}XrayPacketTunnelProvider {"{}"}</code></pre>
            <a className="text-link" href={`${mobileUrl}#apple`}>Apple setup guide ↗</a>
          </article>
          <article className="sdk-card">
            <div className="sdk-title"><span className="platform-icon android">A</span><div><p>Android</p><h3>VpnService adapter</h3></div></div>
            <pre><code>dependencies {" {\n    "}implementation({"\n        "}<span>&quot;io.github.aimalygin:xray-rust-mobile:0.3.2&quot;</span>{"\n    "}){"\n}"}</code></pre>
            <a className="text-link" href={`${mobileUrl}#android`}>Android setup guide ↗</a>
          </article>
        </div>
      </section>

      <section className="section release-section">
        <div className="shell release-grid">
          <div>
            <p className="eyebrow">Release integrity</p>
            <h2>Binary releases you can verify.</h2>
          </div>
          <div className="release-copy">
            <p>Each mobile release records the wrapper version, exact core revision, binary revision, and checksums. The same source is available if you prefer to build it yourself.</p>
            <div className="release-points"><span>✓ Pinned core revision</span><span>✓ SHA-256 checksums</span><span>✓ Reproducible metadata</span></div>
            <a className="button secondary" href={`${mobileUrl}/releases`}>View releases</a>
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
        <div><a href={coreUrl}>Core</a><a href={mobileUrl}>Mobile</a><a href={`${coreUrl}/blob/main/LICENSE`}>License</a></div>
      </footer>
    </main>
  );
}
