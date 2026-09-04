import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const distDir = new URL("../dist", import.meta.url).pathname;
const html = readFileSync(join(distDir, "index.html"), "utf8");

// Concatenate every stylesheet Astro emitted. The bundle filenames are derived
// from whichever component owns the styles and change when the component graph
// changes, so matching one by name (it used to be `index.*.css`) makes the
// suite fail for a reason that has nothing to do with the site.
const astroDir = join(distDir, "_astro");
const css = readdirSync(astroDir)
  .filter((f) => f.endsWith(".css"))
  .map((f) => readFileSync(join(astroDir, f), "utf8"))
  .join("\n");

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

test("at least one stylesheet was emitted", () => {
  assert.ok(css.length > 0, "no CSS found in dist/_astro");
});
