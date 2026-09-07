import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, main, scanText, RULES } from "../tools/scan-dist.mjs";

// FIXTURE RULE: never plant a real estate identifier here. This repository is
// public and these strings are the ones a reader will copy out of it. Planted
// addresses are 172.31.255.253/.254 — inside RFC 1918 (so they exercise the
// rfc1918-ipv4 rule identically) and outside every range this lab uses, so
// they disclose neither a host nor a subnet. Planted hostnames use the RFC
// 2606 `example.` second label. An earlier round removed the real hostnames
// from these fixtures and left the real addresses behind; the two are the same
// defect, and the addresses were worse, because one of them also names the
// management /24.

const REAL_DIST = new URL("../dist", import.meta.url).pathname;
const BASELINE = new URL("../tools/scan-baseline.json", import.meta.url).pathname;

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), "tripwire-"));
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

test("the real build is clean, and the baseline is empty", () => {
  const { code, findings } = run(REAL_DIST, BASELINE);
  assert.deepEqual(findings, []);
  assert.equal(code, 0);
});

test("a planted private address fails the build", () => {
  const dir = fixture({ "index.html": "<p>ssh to 172.31.255.254 for logs</p>" });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].rule, "rfc1918-ipv4");
  assert.equal(findings[0].match, "172.31.255.254");
});

test("a planted internal hostname fails the build", () => {
  const dir = fixture({ "index.html": "<p>see db01.example.internal</p>" });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].rule, "private-use-fqdn");
});

test("planted key material fails the build", () => {
  const dir = fixture({
    "index.html": "<p>ok</p>",
    "leak.txt": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
  });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].rule, "pem-private-key");
});

test("a secret rendered from a component is caught, because the scan reads dist", () => {
  // PKG-21 review round 4: a claim rendered from an imported component never
  // appears in a route file. Neither does a leaked string.
  const dir = fixture({
    "index.html": "<p>nothing here</p>",
    "_astro/Explorer.abc.js": 'const n={detail:"reachable at web02.example.internal"};',
  });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].file, "_astro/Explorer.abc.js");
});

// The extension allowlist was a demonstrated bypass: Astro copies public/
// into dist/ verbatim, and a file whose extension was not in the old
// SCANNABLE set was published without ever being opened. These four pin the
// inverted behaviour — scan by default, and refuse to ship a type nobody has
// classified.
test("a secret in a public/ passthrough file is caught, not skipped", () => {
  const dir = fixture({
    "index.html": "<p>ok</p>",
    // Plain `password:`, not `db_password:` — the rule anchors on \b, so a
    // word-character prefix defeats it. That is a real gap, deliberately not
    // widened here: it changes rule surface against a build nobody measured.
    "notes.yaml": "password: hunter2abcdef\nhost: 172.31.255.254\n",
  });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  const rules = new Set(findings.map((f) => f.rule));
  assert.ok(rules.has("rfc1918-ipv4"), `expected the address, got ${[...rules]}`);
  assert.ok(rules.has("credential-assignment"), `expected the password, got ${[...rules]}`);
  assert.ok(findings.every((f) => f.file === "notes.yaml"));
});

test("an AWS key in a .env copied through public/ is caught", () => {
  const dir = fixture({
    "index.html": "<p>ok</p>",
    "creds.env": "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n",
  });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].file, "creds.env");
  assert.equal(findings[0].rule, "aws-access-key-id");
});

test("an unclassified extension stops the build instead of slipping past", () => {
  const dir = fixture({ "index.html": "<p>ok</p>", "payload.bin": "whatever" });
  const { code, findings, reason } = run(dir, BASELINE);
  assert.equal(code, 2, "an unopened file is an unscanned file — it must fail closed");
  assert.deepEqual(findings, []);
  assert.match(reason, /payload\.bin/);
});

test("an extensionless file stops the build too", () => {
  // `_headers`, `_redirects`, `CNAME`: real things that land in dist/ from
  // public/, all extensionless, none of them classified until someone says so.
  const dir = fixture({ "index.html": "<p>ok</p>", _headers: "/*\n  X-Frame-Options: DENY\n" });
  const { code, reason } = run(dir, BASELINE);
  assert.equal(code, 2);
  assert.match(reason, /_headers/);
});

test("a known-binary extension is skipped without stopping the build", () => {
  const dir = fixture({ "index.html": "<p>ok</p>", "font.woff2": "wOF2binary" });
  const { code, scanned } = run(dir, BASELINE);
  assert.equal(code, 0);
  assert.equal(scanned, 1, "the font must be skipped, not scanned, and not unclassified");
});

test("minified property access is not a hostname", () => {
  // The single-label form of this rule produced 20 findings against the real
  // build, all of them @xyflow/react property access. Design §1.3.
  const js = "if(e.local){n.local=t.local}else{r.local=e.n.local}";
  assert.deepEqual(scanText("bundle.js", js), []);
});

test("asset hashes and CSS custom properties are not high-entropy secrets", () => {
  const css = "--xy-controls-button-background-color-hover-default:#fff;";
  const js = 'import"/_astro/instrument-serif-latin-400-normal.woff2";';
  assert.deepEqual(scanText("a.css", css), []);
  assert.deepEqual(scanText("a.js", js), []);
});

test("a real high-entropy secret is caught", () => {
  const found = scanText("x.html", "token " + "aB3".repeat(20));
  assert.equal(found.length, 1);
  assert.equal(found[0].rule, "high-entropy-run");
});

test("a secret is not smuggled past the scanner behind a data URI prefix", () => {
  // A prior version of scanText stripped data: URIs with a greedy
  // base64-alphabet match and no boundary, which ate any secret-shaped
  // string typed immediately after a `data:...;base64,` prefix.
  const found = scanText(
    "x.html", "contact data:x/y;base64,AKIAABCDEFGHIJKLMNOP now");
  assert.equal(found.length, 1);
  assert.equal(found[0].rule, "aws-access-key-id");
  assert.equal(found[0].match, "AKIAABCDEFGHIJKLMNOP");
});

test("a credential split across inline markup is caught", () => {
  // The reader sees "password: hunter2abcdef"; a raw-markup scan sees tags in
  // between and reports clean. Same failure as the data: URI exclusion — the
  // scanner reading a different representation than the person on the page.
  const found = scanText("x.html", "<p><code>password</code>: <code>hunter2abcdef</code></p>");
  assert.equal(found.length, 1);
  assert.equal(found[0].rule, "credential-assignment");
});

test("an unsplit secret in HTML is reported once, not twice", () => {
  // It matches in both the raw and the rendered pass; dedupe is by rule+match.
  const found = scanText("x.html", "<p>password: hunter2abcdef</p>");
  assert.equal(found.length, 1);
});

test("script and style bodies are not double-reported", () => {
  const found = scanText("x.html", "<script>var t=\"password: hunter2abcdef\";</script>");
  assert.equal(found.length, 1);
});

test("a temporary AWS access-key ID is caught, not just a long-term one", () => {
  // ASIA keys are 20 chars, under the entropy rule's 40-char floor, so if the
  // prefix is missed nothing else catches them.
  assert.equal(scanText("x.html", "ASIAABCDEFGHIJKLMNOP")[0].rule, "aws-access-key-id");
  assert.equal(scanText("x.html", "AKIAABCDEFGHIJKLMNOP")[0].rule, "aws-access-key-id");
});

test("compressed text is not classified as binary", () => {
  // .svgz and .gz are compressed TEXT. Listing them as binary would skip a file
  // whose content this scanner exists to read; unlisted means exit 2 instead.
  const dir = fixture({ "index.html": "<p>ok</p>", "map.svgz": "\u001f\u008b binary-ish" });
  assert.equal(run(dir, BASELINE).code, 2);
});

test("a dotfile is scanned by its full name, not a missing extension", () => {
  // extname(".env") is "" — without dotfile handling this exited 2 rather than
  // reading the file, even though ".env" is in the scanned set.
  const dir = fixture({ "index.html": "<p>ok</p>", ".env": "password=hunter2abcdef\n" });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].rule, "credential-assignment");
});

test("a build of .htm pages is scanned, not rejected as pageless", () => {
  // The structural check demanded ".html" while classification accepted
  // .htm/.xhtml, so this dist was scanned and THEN failed as "no built HTML".
  const dir = fixture({ "index.htm": "<p>ssh to 172.31.255.254</p>" });
  const { code, findings } = run(dir, BASELINE);
  assert.equal(code, 1);
  assert.equal(findings[0].rule, "rfc1918-ipv4");
});

test("an .xhtml page also counts as a page", () => {
  const dir = fixture({ "index.xhtml": "<p>clean</p>" });
  assert.equal(run(dir, BASELINE).code, 0);
});

test("the CLI does not print matched secrets by default", () => {
  // This scan runs in GitHub Actions on a PUBLIC repo: printing a real match
  // would copy the secret into a world-readable log.
  const dir = fixture({ "index.html": "<p>ssh to 172.31.255.254</p>" });
  const lines = [];
  const realError = console.error;
  const realEnv = process.env.SCAN_SHOW_MATCHES;
  console.error = (...a) => lines.push(a.join(" "));
  try {
    delete process.env.SCAN_SHOW_MATCHES;
    assert.equal(main([dir, BASELINE]), 1);
  } finally {
    console.error = realError;
    if (realEnv === undefined) delete process.env.SCAN_SHOW_MATCHES;
    else process.env.SCAN_SHOW_MATCHES = realEnv;
  }
  const out = lines.join("\n");
  assert.ok(!out.includes("172.31.255.254"), `CLI leaked the match: ${out}`);
  assert.match(out, /redacted/);
  assert.match(out, /rfc1918-ipv4/, "the rule and file must still be reported");
});

test("SCAN_SHOW_MATCHES=1 reveals the match, so a baseline entry can be written", () => {
  const dir = fixture({ "index.html": "<p>ssh to 172.31.255.254</p>" });
  const lines = [];
  const realError = console.error;
  const realEnv = process.env.SCAN_SHOW_MATCHES;
  console.error = (...a) => lines.push(a.join(" "));
  try {
    process.env.SCAN_SHOW_MATCHES = "1";
    main([dir, BASELINE]);
  } finally {
    console.error = realError;
    if (realEnv === undefined) delete process.env.SCAN_SHOW_MATCHES;
    else process.env.SCAN_SHOW_MATCHES = realEnv;
  }
  assert.match(lines.join("\n"), /172\.31\.255\.254/);
});

test("a missing dist fails closed, not green", () => {
  assert.equal(run(join(tmpdir(), "definitely-not-here-42"), BASELINE).code, 2);
});

test("an empty dist fails closed, not green", () => {
  assert.equal(run(mkdtempSync(join(tmpdir(), "empty-")), BASELINE).code, 2);
});

test("a dist with no HTML fails closed, not green", () => {
  const dir = fixture({ "only.css": "body{color:red}" });
  assert.equal(run(dir, BASELINE).code, 2);
});

test("the baseline suppresses an exact known-clean match and nothing else", () => {
  const dir = fixture({ "index.html": "<p>172.31.255.254 and 172.31.255.253</p>" });
  const bl = fixture({ "b.json": JSON.stringify(["172.31.255.254"]) });
  const { code, findings } = run(dir, join(bl, "b.json"));
  assert.equal(code, 1);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].match, "172.31.255.253");
});

test("a credential in JSON form is caught, quotes and all", () => {
  // Astro serializes island props as JSON, and \s*[=:] cannot cross a closing
  // quote — so this exact shape scored zero before the optional quote was
  // added to the rule.
  const found = scanText("x.html", '<script>{"token":"hunter2abcdef"}</script>');
  assert.equal(found.length, 1);
  assert.equal(found[0].rule, "credential-assignment");

  const spaced = scanText("props.json", '{"api_key": "hunter2abcdef"}');
  assert.equal(spaced.length, 1);
  assert.equal(spaced[0].rule, "credential-assignment");
});

test("a malformed baseline fails closed as a structural error, not as findings", () => {
  // JSON.parse used to throw straight out of run(), so the CLI died with a
  // stack trace and exit 1 — reporting a broken scanner as a leak.
  const dir = fixture({ "index.html": "<p>ok</p>" });
  const bl = fixture({ "b.json": "{not json" });
  const { code, findings, reason } = run(dir, join(bl, "b.json"));
  assert.equal(code, 2);
  assert.deepEqual(findings, []);
  assert.match(reason, /cannot read/i);
});

test("a baseline that is not an array of strings fails closed", () => {
  const dir = fixture({ "index.html": "<p>ok</p>" });
  const bl = fixture({ "b.json": JSON.stringify({ "172.31.255.254": true }) });
  assert.equal(run(dir, join(bl, "b.json")).code, 2);

  const bl2 = fixture({ "b.json": JSON.stringify(["ok", 42]) });
  assert.equal(run(dir, join(bl2, "b.json")).code, 2);
});

test("a dist path that is a file, not a directory, fails closed", () => {
  const dir = fixture({ "index.html": "<p>ok</p>" });
  const { code, reason } = run(join(dir, "index.html"), BASELINE);
  assert.equal(code, 2, "ENOTDIR must return 2, not throw out of run()");
  assert.match(reason, /cannot walk/i);
});

test("the CLI never reports a structural failure as findings", () => {
  // The exit contract is the point of D11: 0 clean, 1 findings, 2 broken.
  const dir = fixture({ "index.html": "<p>ok</p>" });
  const bl = fixture({ "b.json": "{not json" });
  assert.equal(main([dir, join(bl, "b.json")]), 2);
});

test("every rule has a distinct name", () => {
  assert.equal(new Set(RULES.map((r) => r.name)).size, RULES.length);
});
