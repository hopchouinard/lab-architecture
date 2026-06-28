import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const distDir = new URL("../dist", import.meta.url).pathname;
const html = readFileSync(join(distDir, "index.html"), "utf8");

// Find the bundled CSS file produced by Astro's build
const astroDir = join(distDir, "_astro");
const cssFile = readdirSync(astroDir).find((f) => f.endsWith(".css") && f.startsWith("index."));
const css = readFileSync(join(astroDir, cssFile), "utf8");

test("overview page renders the brand and sidebar nav", () => {
  assert.match(html, /Patchoutech/);
  assert.match(html, /The Thesis/);
  assert.match(html, /Describe/);
});

test("overview page renders the thesis hero copy", () => {
  assert.match(html, /three boundaries/i);
  assert.match(html, /one source of truth/i);
});

test("overview page applies the copper accent token", () => {
  assert.match(css, /#cf7e38/);
});
