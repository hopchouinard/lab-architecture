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
import { join, relative } from "node:path";

const srcDir = new URL("../src", import.meta.url).pathname;
const pagesDir = join(srcDir, "pages");

// Every routable extension, discovered recursively. A flat `.astro`-only scan
// silently skips a nested route (src/pages/guides/x.astro) and every Markdown
// or MDX page — and @astrojs/mdx is installed here, so those are real routes.
// A guard that does not see a page cannot guard it.
const PAGE_EXT = /\.(astro|md|mdx|markdown|html)$/i;

function collectPages(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectPages(full));
    } else if (PAGE_EXT.test(entry.name)) {
      out.push({ name: relative(pagesDir, full), text: readFileSync(full, "utf8") });
    }
  }
  return out;
}

const pages = collectPages(pagesDir);

const graph = readFileSync(join(srcDir, "data", "graph.ts"), "utf8");

// The published corpus: what a reader actually receives, not what a route file
// happens to contain. A route that renders prose from a component or a data
// module ships that prose, and a source-only scan never opens either — so a
// retired claim could pass the gate and still appear on the page. Every
// "must not appear" guard runs over this; the source scan stays for the checks
// that need per-file attribution and structure.
const distDir = new URL("../dist", import.meta.url).pathname;

function collectBuilt(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectBuilt(full));
    } else if (/\.html$/i.test(entry.name)) {
      // Tags stripped and whitespace collapsed: the prose wraps <strong> and
      // <code> mid-sentence, and a sentence-scoped regex must see the sentence.
      const text = readFileSync(full, "utf8")
        .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/\s+/g, " ");
      out.push({ name: relative(distDir, full), text });
    } else if (/\.js$/i.test(entry.name)) {
      // The explorer's graph ships inside the client bundle, so its node prose
      // is published text even though no HTML file contains it at build time.
      out.push({ name: relative(distDir, full), text: readFileSync(full, "utf8") });
    }
  }
  return out;
}

const built = collectBuilt(distDir);

test("the build produced a corpus to check", () => {
  assert.ok(
    built.some((f) => f.name.endsWith(".html")),
    "no built HTML found in dist/ — run `npm run build` first; an empty corpus makes every guard below vacuous",
  );
});

test("the retired audit-trail claim does not come back", () => {
  // agent-ops derives events FROM the operator ledger; the ledger is the sole
  // audit authority and the stream is a one-way mirror of it. Any wording that
  // collapses the two into one record is false.
  const retired = [
    /the log is the audit trail/i,
    /no separate audit log/i,
    /the two records are.{0,20}the same record/i,
  ];
  for (const { name, text } of [...pages, ...built]) {
    for (const pattern of retired) {
      assert.doesNotMatch(text, pattern, `${name} revives a retired audit-trail claim: ${pattern}`);
    }
  }
});

// Present-indicative assertions that the projection or tripwire is running.
// Each one is a sentence that was actually published while false, so this list
// grows by observation rather than by imagination.
const RUNNING_MECHANISM = [
  /tripwire (runs|scans|then runs|fires|catches)/i,
  /(the )?allowlist (runs|projection runs)/i,
  /(scan|projection) then runs/i,
  /(both checks|both guards) must (both )?pass/i,
  /must both pass/i,
  /it is a hard gate/i,
  /exits non-zero and the site does not ship/i,
  /the build fails\b/i,
  /fails it if anything secret-shaped/i,
];

// Each unbuilt mechanism is checked SEPARATELY. A page-level "some disclaimer
// exists somewhere" match is not enough: a page naming both mechanisms can
// disclaim one and assert the other, and the page-level form passes it.
const MECHANISMS = ["tripwire", "allowlist projection", "publish projection"];
const UNBUILT =
  "does not exist|do not exist|nor the [a-z ]*exists|neither[^.!?]{0,40}exists|not built|not yet built|designed and not|designed but not|designed, not built|neither is built|would ";

/** The mechanism and an unbuilt marker inside one sentence, in either order. */
function disclaimerFor(mechanism) {
  const m = mechanism.replace(/ /g, "\\s+");
  return new RegExp(
    `((${m})[^.!?]{0,200}(${UNBUILT}))|((${UNBUILT})[^.!?]{0,200}(${m}))`,
    "i",
  );
}

test("every unbuilt mechanism a page names is disclaimed in the same sentence", () => {
  // Source AND rendered output: a mechanism named by an imported component
  // reaches the reader, and checking only route source would let it through
  // with no disclaimer at all.
  for (const { name, text } of [...pages, ...built.filter((f) => f.name.endsWith(".html"))]) {
    for (const mechanism of MECHANISMS) {
      if (!new RegExp(mechanism.replace(/ /g, "\\s+"), "i").test(text)) continue;
      assert.match(
        text,
        disclaimerFor(mechanism),
        `${name} names "${mechanism}" without saying, in the same sentence, that it is unbuilt`,
      );
    }

  }

  for (const { name, text } of built) {
    for (const pattern of RUNNING_MECHANISM) {
      assert.doesNotMatch(
        text,
        pattern,
        `${name} asserts an unbuilt publish mechanism is running: ${pattern}`,
      );
    }
  }
  // Per node, not per file: a single "designed, not built" anywhere in graph.ts
  // would let the OTHER node be flipped back to a present-tense claim while the
  // assertion still passed, and graph.ts feeds the public explorer directly.
  for (const id of ["allowlist", "tripwire"]) {
    const node = graph.match(new RegExp(`id:\\s*"${id}"[\\s\\S]{0,700}?\\n  \\}`));
    assert.ok(node, `graph.ts no longer has a node with id "${id}" — update this guard`);

    // The `kind` field specifically: Explorer.tsx renders it as the node's
    // visible tag, and a match anywhere in the object would stay green while
    // kind was flipped back and the label survived only in `detail`.
    const kind = node[0].match(/kind:\s*"([^"]*)"/);
    assert.ok(kind, `graph.ts node "${id}" has no kind field — update this guard`);
    assert.equal(
      kind[1],
      "designed, not built",
      `graph.ts node "${id}" must carry kind: "designed, not built" — the explorer renders this field`,
    );
  }
});

test("no page claims this site is generated from the inventory", () => {
  const retired = [
    /pre-sanitized (data|json)/i,
    /cleared the allowlist projection/i,
    /passed through the same allowlist projection/i,
    // The site listed among the inventory's rendered views. This one shipped
    // in the first correction and was caught in review, not by this guard.
    /public site[^.!?]{0,160}(rendered differently|the same fact)/i,
    /(this|the public) site is[^.!?]{0,80}(generated|derived|projected) from/i,
  ];
  for (const { name, text } of [...pages, ...built]) {
    for (const pattern of retired) {
      assert.doesNotMatch(text, pattern, `${name} claims generated provenance the site does not have: ${pattern}`);
    }
  }
});

test("the explorer's physical graph still declares itself hand-authored", () => {
  assert.match(graph, /hand-authored/i);
  assert.match(graph, /generic/i);
});
