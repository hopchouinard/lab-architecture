// Claim guards.
//
// Every claim on this site is checked against the live estate before it ships.
// Three of those checks are cheap enough to automate, and each one exists
// because the claim it guards was published while false:
//
//   1. "the log is the audit trail" was ruled false on 2026-07-01, recorded as
//      corrected on 2026-07-03, and was still serving live on 2026-09-04. A
//      claim believed fixed is exactly the kind that nobody re-reads.
//   2. The allowlist projection and the output tripwire are designed and not
//      built. Any page that names them must also say so, in the same file.
//   3. No real lab data is imported here. If that ever changes, mechanisms 1
//      and 2 have to exist first — so the pages must stop saying they do not.
//
// These are string checks over source, not a substitute for the claim-by-claim
// pass against the estate. They only stop a known-false claim from returning.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const srcDir = new URL("../src", import.meta.url).pathname;
const pagesDir = join(srcDir, "pages");

const pages = readdirSync(pagesDir)
  .filter((f) => f.endsWith(".astro"))
  .map((f) => ({ name: f, text: readFileSync(join(pagesDir, f), "utf8") }));

const graph = readFileSync(join(srcDir, "data", "graph.ts"), "utf8");

test("the retired audit-trail claim does not come back", () => {
  // agent-ops derives events FROM the operator ledger; the ledger is the sole
  // audit authority and the stream is a one-way mirror of it. Any wording that
  // collapses the two into one record is false.
  const retired = [
    /the log is the audit trail/i,
    /no separate audit log/i,
    /the two records are.{0,20}the same record/i,
  ];
  for (const { name, text } of pages) {
    for (const pattern of retired) {
      assert.doesNotMatch(text, pattern, `${name} revives a retired audit-trail claim: ${pattern}`);
    }
  }
});

test("pages that name the projection or tripwire also say they are not built", () => {
  const names = /tripwire|allowlist projection|publish projection/i;
  const disclaims = /designed and not|designed but not|designed, not built|not built|does not exist|neither is built|is ever built|would /i;
  for (const { name, text } of pages) {
    if (names.test(text)) {
      assert.match(text, disclaims, `${name} names an unbuilt publish mechanism without saying it is unbuilt`);
    }
  }
  assert.match(graph, /designed, not built/, "graph.ts must label the unbuilt publish nodes");
});

test("no page claims this site is generated from the inventory", () => {
  const retired = [
    /pre-sanitized (data|json)/i,
    /cleared the allowlist projection/i,
    /passed through the same allowlist projection/i,
  ];
  for (const { name, text } of pages) {
    for (const pattern of retired) {
      assert.doesNotMatch(text, pattern, `${name} claims generated provenance the site does not have: ${pattern}`);
    }
  }
});

test("the explorer's physical graph still declares itself hand-authored", () => {
  assert.match(graph, /hand-authored/i);
  assert.match(graph, /generic/i);
});
