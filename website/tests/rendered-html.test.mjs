import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function fetchFromBuild(path = "/", headers = {}) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`https://xray-rust.example${path}`, {
      headers: { accept: "text/html", host: "xray-rust.example", ...headers },
    }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the complete project landing page", async () => {
  const response = await fetchFromBuild();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>xray-rust — VLESS, REALITY, and Vision in Rust<\/title>/i);
  assert.match(html, /A focused Xray client core built for mobile\./);
  assert.match(html, /VLESS, REALITY, Vision/);
  assert.match(html, /application\/ld\+json/);
  assert.match(html, /SoftwareSourceCode/);
  assert.match(html, /FAQPage/);
  assert.match(html, /og:image/);
  assert.doesNotMatch(html, /experimental/i);
  assert.doesNotMatch(html, /starter|codex-preview/i);
});

test("publishes crawler and LLM discovery files", async () => {
  const [robots, sitemap, llms, full] = await Promise.all([
    fetchFromBuild("/robots.txt"),
    fetchFromBuild("/sitemap.xml"),
    readFile(new URL("../dist/client/llms.txt", import.meta.url), "utf8"),
    readFile(new URL("../dist/client/llms-full.txt", import.meta.url), "utf8"),
  ]);

  assert.equal(robots.status, 200);
  assert.match(await robots.text(), /OAI-SearchBot[\s\S]*GPTBot/);
  assert.equal(sitemap.status, 200);
  assert.match(await sitemap.text(), /https:\/\/xray-rust\.example/);
  assert.match(llms, /Core repository/);
  assert.match(full, /Published benchmark snapshot/);
});
