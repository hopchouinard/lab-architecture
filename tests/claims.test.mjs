// Claim guards.
//
// Every claim on this site is checked against the live estate before it ships.
// These are string checks over source and built output, not a substitute for
// the claim-by-claim pass — they only stop a known-false claim from returning.
//
//   1. "the log is the audit trail" was ruled false on 2026-07-01, recorded as
//      corrected on 2026-07-03, and was still serving live on 2026-09-04. A
//      claim believed fixed is exactly the kind that nobody re-reads.
//   2. The tripwire is BUILT and runs on every build of this site. That claim
//      is verifiable from inside this repository, so a guard below proves it by
//      asserting both workflows invoke it. If the step is ever removed, the
//      page's present-tense claim goes red rather than quietly false.
//   3. The allowlist projection is built in the DESCRIBE repository and is
//      deliberately not wired to this site. No test here can verify code in
//      another repo, so its sentences must carry the not-wired qualifier — an
//      unverifiable present-tense claim is exactly the shape of the one that
//      sat false for three months.
//   4. No real lab data is imported here. That is still true and is still the
//      claim that would actually cause harm, so its guard is unchanged.

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
      // Whitespace collapsed, same as collectBuilt below: a required phrase must
      // not be defeated by where a line happens to wrap in source. Without this,
      // prose is hostage to the regex instead of the other way round — a page
      // author reflowing a paragraph could red the build for no semantic reason.
      const text = readFileSync(full, "utf8").replace(/\s+/g, " ");
      out.push({ name: relative(pagesDir, full), text });
    }
  }
  return out;
}

const pages = collectPages(pagesDir);

// README.md is published on github.com, which makes it a page of this site by
// every measure except the routing table. It shipped "nothing scans the
// result" and "designed and not built" for the whole of the round that
// corrected those exact claims on four .astro pages, because the corpus
// stopped at src/pages/**. A claim guard that does not read the landing page
// is a claim guard with a landing-page-shaped hole in it.
const readme = {
  name: "README.md",
  text: readFileSync(new URL("../README.md", import.meta.url).pathname, "utf8")
    .replace(/\s+/g, " "),
};

// Everything a human writes by hand, in one corpus. Every "must not appear"
// guard below runs over this plus the built output.
const authored = [...pages, readme];

const graph = readFileSync(join(srcDir, "data", "graph.ts"), "utf8");

// graph.ts carries mechanism claims in prose — a node `detail` is published
// text — and it ships inside the JS bundle rather than any HTML file, so the
// source scan (src/pages/** only) and the built scan (.html only, for the
// sentence-level guards) both missed it. Whitespace collapsed for the same
// reason the other two corpora collapse it: a required phrase must not be
// defeated by where a line happens to wrap.
const graphSource = { name: "src/data/graph.ts", text: graph.replace(/\s+/g, " ") };

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
    // The ledger records refusals too. Verified against the live ledger on
    // 2026-09-04: 63 success, 25 failure, 2 staged, 2 blocked. Any wording
    // that equates a log entry with a permitted action denies 27 of them.
    /every log entry corresponds to an action that was permitted/i,
    /(log|ledger|audit trail)[^.!?]{0,60}only (contains|records|holds) (successful|permitted)/i,
  ];
  for (const { name, text } of [...authored, ...built]) {
    for (const pattern of retired) {
      assert.doesNotMatch(text, pattern, `${name} revives a retired audit-trail claim: ${pattern}`);
    }
  }
});

// The projection lives in another repository, so this suite cannot prove it
// exists. Every sentence naming it must therefore say it is not wired to this
// site — the same per-sentence discipline the old disclaimer guard applied,
// pointed at the wording that is now true.
//
// The phrase is TWO WORDS on purpose. operate.astro and governed-autonomy.astro
// describe the capability registry as "an allowlist of every operation the
// agent may attempt". That mechanism exists, works, and has nothing to do with
// this one; a bare-word match reds two correct pages, and the tempting "fix" is
// to bolt a false disclaimer onto a true sentence.
const PROJECTION_NAMES = ["allowlist projection", "publish projection"];

// Deliberately narrow to alternatives that name the WIRING relationship, not
// generic nearby-sounding phrasing. An earlier draft also accepted "no lab
// data is imported", "never touches", and "does not reach this" — but none of
// those say the projection itself is disconnected, and "no lab data is
// imported" is stock phrasing that already appears elsewhere in this same
// prose for an unrelated reason (the hand-authoring guarantee). A sentence
// like "the allowlist projection now feeds this site directly because no lab
// data is imported through any other channel" passed the looser form while
// asserting exactly the false, present-tense, wired claim this guard exists
// to prevent. A qualifier that does not mention the connection can be
// satisfied by a sentence asserting the opposite of what it is meant to rule
// out.
const NOT_WIRED_RE = /\bnot wired\b|\bnot connected\b/i;

/** Sentences, roughly. Good enough: the unit is "one claim". */
function sentences(text) {
  return text.split(/(?<=[.!?])\s+/);
}

function unqualifiedSentences(text, mechanism) {
  const m = new RegExp(mechanism.replace(/ /g, "\\s+"), "i");
  return sentences(text).filter((s) => m.test(s) && !NOT_WIRED_RE.test(s));
}

// The qualifier guard is per-sentence and needs attributable text, so it runs
// over the hand-written sources plus the built HTML. graph.ts is in it because
// it is one of the files this change edits and it makes mechanism claims.
const QUALIFIER_CORPUS = [
  ...authored,
  graphSource,
  ...built.filter((f) => f.name.endsWith(".html")),
];

// The positive guard above is POSITIONAL: it asks only that a not-wired phrase
// appear somewhere in the sentence. A compound sentence can therefore attach
// the qualifier to a different subject and pass while asserting the opposite —
// "The allowlist projection now drives this site, and the old curated graph is
// not connected any more" satisfies it completely.
//
// So the fail-closed half: a list of relationships this site does not have,
// which must appear NOWHERE. The two guards are much stronger together than
// either is alone — one requires the disclaimer, the other rejects the claim,
// and a sentence has to get past both.
//
// The verbs are third-person present forms on purpose. Those are the assertion
// forms; "could one day drive this layer" is a hypothesis and graph.ts is
// allowed to state it.
const FALSE_MECHANISM_CLAIMS = [
  /(allowlist|publish) projection[^.!?]{0,80}\b(feeds|drives|powers|generates|is wired to|is connected to)\b/i,
  // Retired 2026-09-06 with the output tripwire. Both wordings shipped: the
  // first on colophon.astro and in README.md, which no guard was reading.
  /nothing scans the (output|result|build)/i,
  /(the )?(build|repository|site) runs no (output )?scan/i,
];

const NEGATIVE_CORPUS = [...authored, graphSource, ...built];

test("no text asserts a mechanism relationship this site does not have", () => {
  for (const { name, text } of NEGATIVE_CORPUS) {
    for (const pattern of FALSE_MECHANISM_CLAIMS) {
      assert.doesNotMatch(
        text, pattern,
        `${name} asserts a mechanism relationship that does not exist: ${pattern}`,
      );
    }
  }
});

test("a compound sentence cannot smuggle a wired claim past the qualifier guard", () => {
  // Both of these pass the positive guard — the qualifier is present, attached
  // to a different subject — and both assert exactly the false, present-tense,
  // wired claim these guards exist to prevent. Pinned so that removing the
  // negative guard, or narrowing its verb list, goes red here.
  const compound = [
    "The allowlist projection now drives this site, and the old curated graph is not connected any more.",
    "The allowlist projection feeds this page directly; the tripwire is not wired to the explorer.",
  ];
  for (const claim of compound) {
    assert.deepEqual(
      unqualifiedSentences(claim, "allowlist projection"), [],
      "precondition: the positive guard is expected to accept this sentence — that is why the negative guard exists",
    );
    assert.ok(
      FALSE_MECHANISM_CLAIMS.some((re) => re.test(claim)),
      `the negative guard misses a compound wired claim: ${claim}`,
    );
  }

  // The retired no-scan claim, in each of the three forms that shipped.
  for (const claim of [
    "An author who types a real identifier into a page publishes it, because nothing scans the output.",
    "The build compiles what it is given and nothing scans the result.",
    "No field carries a publication marker and this repository's build runs no output scan.",
  ]) {
    assert.ok(
      FALSE_MECHANISM_CLAIMS.some((re) => re.test(claim)),
      `the negative guard misses a retired no-scan claim: ${claim}`,
    );
  }
});

test("every sentence naming the projection says it is not wired to this site", () => {
  for (const { name, text } of QUALIFIER_CORPUS) {
    for (const mechanism of PROJECTION_NAMES) {
      const bad = unqualifiedSentences(text, mechanism);
      assert.deepEqual(
        bad,
        [],
        `${name} names "${mechanism}" in ${bad.length} sentence(s) that do not say it is unwired: ${JSON.stringify(bad.slice(0, 2))}`,
      );
    }
  }
});

// A false, present-tense, wired claim can hide behind stock phrasing that
// sounds like a disclaimer without saying anything about the connection. This
// exact sentence passed an earlier, looser form of NOT_WIRED_RE — pinned here
// so that loosening it again reintroduces a claim this guard exists to catch.
test("a stock-phrasing sentence asserting the projection IS wired is not mistaken for a disclaimer", () => {
  const falseClaim =
    "The allowlist projection now feeds this site directly because no lab data is imported through any other channel.";
  const bad = unqualifiedSentences(falseClaim, "allowlist projection");
  assert.deepEqual(
    bad,
    [falseClaim],
    "NOT_WIRED_RE accepted a sentence asserting the projection IS wired — it must reject anything that does not name the connection itself",
  );
});

test("both workflows run the tripwire, so the present-tense claim stays earned", () => {
  const workflows = new URL("../.github/workflows", import.meta.url).pathname;

  // What `npm run scan` actually runs. Asserting only that the workflows
  // invoke it leaves `"scan": "true"` green: every assertion below would pass
  // while the gate ran a command that exits 0 over nothing.
  const pkg = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url).pathname, "utf8"));
  assert.match(
    pkg.scripts.scan, /tools\/scan-dist\.mjs/,
    "package.json's scan script no longer runs the tripwire — the workflow steps below would gate nothing",
  );

  for (const wf of ["ci.yml", "deploy.yml"]) {
    const text = readFileSync(join(workflows, wf), "utf8");
    // Deliberately not anchored to `- run: npm run scan`: refactoring the step
    // to a two-line `- name:` / `run:` form is correct and must not red this
    // suite. The ordering assertion below is what makes placement matter.
    assert.ok(
      text.includes("npm run scan"),
      `${wf} does not run the tripwire — the site claims it runs on every build`,
    );
    // A gate that cannot fail the build is not a gate. Checked over the whole
    // file, not just the scan step: continue-on-error anywhere in these two
    // short workflows is either this defect or something needing its own
    // review, and neither should land silently.
    assert.doesNotMatch(
      text, /continue-on-error/i,
      `${wf} contains continue-on-error — a step that reports red as green gates nothing`,
    );
  }
  const deploy = readFileSync(join(workflows, "deploy.yml"), "utf8");
  assert.ok(
    deploy.indexOf("npm run scan") < deploy.indexOf("wrangler-action"),
    "the scan must precede the deploy step, or it gates nothing",
  );
});

test("the explorer graph's publish nodes carry their built status", () => {
  // Per node, not per file: one correct kind anywhere in graph.ts would let the
  // OTHER node be flipped while the assertion still passed, and graph.ts feeds
  // the public explorer directly. The `kind` field specifically, because
  // Explorer.tsx renders it as the node's visible tag.
  const expected = { allowlist: "built, not wired", tripwire: "enforced on every build" };
  for (const [id, want] of Object.entries(expected)) {
    const node = graph.match(new RegExp(`id:\\s*"${id}"[\\s\\S]{0,700}?\\n  \\}`));
    assert.ok(node, `graph.ts no longer has a node with id "${id}" — update this guard`);
    const kind = node[0].match(/kind:\s*"([^"]*)"/);
    assert.ok(kind, `graph.ts node "${id}" has no kind field — update this guard`);
    assert.equal(kind[1], want,
      `graph.ts node "${id}" must carry kind: "${want}" — the explorer renders this field`);
  }

  // The node body, not just the kind tag. A `detail` establishes its subject
  // from the node it belongs to, so its prose says "it", and neither the
  // sentence-scoped qualifier guard nor the negative guard can see a pronoun.
  // "It is wired to this site and it feeds every page" passes both of them
  // inside this node while `kind` still reads "built, not wired". Scope the
  // check to the node instead: the allowlist node's own text must carry the
  // disclaimer somewhere in it.
  //
  // The `detail` field specifically, NOT the whole node: `kind` already reads
  // "built, not wired", so a whole-node match is satisfied by the tag it is
  // supposed to be corroborating and asserts nothing about the prose.
  const allowlist = graph.match(/id:\s*"allowlist"[\s\S]{0,700}?\n  \}/)[0];
  const detail = allowlist.match(/detail:\s*\n?\s*"((?:[^"\\]|\\.)*)"/);
  assert.ok(detail, 'graph.ts node "allowlist" has no detail field — update this guard');
  assert.match(
    detail[1], NOT_WIRED_RE,
    'graph.ts\'s "allowlist" detail no longer says the projection is unwired — the explorer publishes this prose verbatim',
  );
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
    // The same relationship stated the other way round. Checking one
    // direction only leaves "inventory.yaml generates this site" green.
    /inventory\.yaml[^.!?]{0,80}(generates|feeds|produces|renders|drives)[^.!?]{0,40}(this|the public) site/i,
    /(the )?inventory[^.!?]{0,60}(is projected|projects)[^.!?]{0,40}(into|onto|to) (this|the public) site/i,
  ];
  for (const { name, text } of [...authored, ...built]) {
    for (const pattern of retired) {
      assert.doesNotMatch(text, pattern, `${name} claims generated provenance the site does not have: ${pattern}`);
    }
  }
});

test("the explorer's physical graph still declares itself hand-authored", () => {
  assert.match(graph, /hand-authored/i);
  assert.match(graph, /generic/i);
});
