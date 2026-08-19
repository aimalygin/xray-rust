# xray-rust website

Source for the public [xray-rust project website](https://xray-rust.aimalygin.chatgpt.site).

The site introduces the Rust core and mobile SDK, publishes the benchmark
summary, and provides structured project information for search engines and LLM
crawlers through Schema.org, `llms.txt`, and `llms-full.txt`.

## Development

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

## Validation

```bash
npm run lint
npm test
```

`npm test` creates a production build and verifies the rendered landing page,
structured metadata, crawler rules, sitemap, and LLM discovery files.

The website is deployed with OpenAI Sites. Its project configuration is stored
in `.openai/hosting.json`.
