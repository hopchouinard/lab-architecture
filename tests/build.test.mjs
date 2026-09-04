import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const distDir = new URL("../dist", import.meta.url).pathname;
const html = readFileSync(join(distDir, "index.html"), "utf8");

// Resolve the stylesheets the overview page actually links, rather than
// concatenating every CSS asset in the build. Matching one by name is brittle
// (the bundle used to be `index.*.css` and is now `Layout.*.css`, derived from
// whichever component owns the styles); concatenating all of them is worse in
// the other direction — this test is named for the overview page, and would
// stay green on another route's stylesheet while the homepage shipped unstyled.
const linkedHrefs = [...html.matchAll(/<link[^>]+rel="stylesheet"[^>]*>/gi)]
  .map((tag) => tag[0].match(/href="([^"]+)"/i))
  .filter(Boolean)
  .map((m) => m[1]);

const css = linkedHrefs
  .map((href) => readFileSync(join(distDir, href.replace(/^\//, "")), "utf8"))
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

test("the overview page links at least one stylesheet", () => {
  assert.ok(
    linkedHrefs.length > 0,
    "index.html links no stylesheet — the copper-token assertion above would be vacuous",
  );
  assert.ok(css.length > 0, "the linked stylesheets are empty");
});
