#!/usr/bin/env node
// Output tripwire: refuse to ship a build containing anything secret-shaped.
//
// It scans BUILT OUTPUT, not source. A claim — or a leaked string — rendered
// from an imported component never appears in a route file, so a source scan
// would report green over it (PKG-21 review round 4).
//
// It knows NOTHING about the lab it protects. Every rule below is a
// self-contained pattern. Handing this repository the inventory, or a digest
// of it, to check against would publish the secrets it exists to keep out:
// this repo is public, and a short corpus of hostnames and private addresses
// is trivially recovered from its hashes.
//
// Exit codes: 0 clean, 1 findings, 2 structural failure (fail-closed).
import { readFileSync, readdirSync, existsSync, realpathSync } from "node:fs";

import { join, relative, extname, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_DIST = join(HERE, "..", "dist");
export const DEFAULT_BASELINE = join(HERE, "scan-baseline.json");

// Extension classification, and it is fail-CLOSED in both directions.
//
// The first version of this file scanned only an allowlist of extensions and
// silently skipped everything else. That is not a whitelist: a whitelist is
// fail-closed only when it enumerates what is PERMITTED. A whitelist of what
// you *look at* is a blacklist of what you ignore, wearing the safer word.
// Astro copies `public/` into `dist/` verbatim, so a `.yaml`, `.env`, `.md`,
// `.webmanifest` or extensionless file shipped and was never opened — a
// reviewer built a dist/ whose notes.yaml held a password and a private
// address and whose creds.env held an AWS key, and the scan reported
// `{code:0, findings:[], scanned:1}`.
//
// So every extension must land in exactly one of the two sets below, and
// anything in neither STOPS THE BUILD (exit 2) rather than sliding past. An
// unopened file is an unscanned file, and the only safe response to a file
// type nobody has classified is to refuse to ship it.

// Opened and scanned. Deliberately generous: when in doubt, scan it. Reading
// a binary as UTF-8 is lossy but harmless — ASCII byte runs still decode, so
// an embedded secret is still found.
//
// `.ico` is here rather than in the binary list below, even though ICO is a
// binary container. The bypass this set exists to close is the `public/`
// passthrough: files Astro copies into the build verbatim, which the bundler
// never inspects. `favicon.ico` is exactly that class of file, it is 15 KB,
// and it scans clean today (verified against the real build). Fonts are not
// that class — they arrive through the bundler from node_modules, no author
// edits one, and they are an order of magnitude larger — so they stay denied.
// One definition, used both to decide a file is an HTML page worth rendering
// AND to decide dist/ contains any pages at all. They disagreed: the structural
// check demanded ".html" while everything else accepted .htm/.xhtml, so a build
// of only .htm pages was scanned and then failed as "no built HTML".
const HTML_EXT = /\.x?html?$/i;

const SCANNED_EXT = new Set([
  ".html", ".htm", ".xhtml", ".js", ".mjs", ".cjs", ".css", ".json", ".map",
  ".svg", ".txt", ".xml", ".md", ".markdown", ".mdx", ".yaml", ".yml",
  ".toml", ".ini", ".cfg", ".conf", ".env", ".webmanifest", ".csv", ".tsv",
  ".ndjson", ".ts", ".tsx", ".jsx", ".sh", ".rss", ".atom", ".vtt", ".srt",
  ".pem", ".key", ".crt", ".cert", ".ico",
]);

// Known-binary, skipped on purpose. Every entry here is a hole in the scan,
// which is why the list is short and why adding to it is a decision rather
// than a convenience.
const KNOWN_BINARY_EXT = new Set([
  ".woff2", ".woff", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg", ".gif",
  // NOTE: .svgz and .gz are deliberately NOT here. They are compressed TEXT,
  // and listing them as binary silently skips a file whose decompressed
  // content this scanner exists to read. Unlisted means exit 2, which forces
  // a human to classify it rather than letting it slip past unread.
  ".webp", ".avif", ".pdf", ".mp4", ".webm", ".zip",
]);

export const RULES = [
  { name: "rfc1918-ipv4", re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
  // TWO labels, the second at least four characters, then a private-use TLD.
  // The single-label form matches minified property access such as `e.local`
  // and produced 20 findings against a clean build, all @xyflow/react
  // property access. Requiring two labels with a longer second one separates
  // a real-shaped hostname from that noise.
  { name: "private-use-fqdn", re: /\b[a-z0-9][a-z0-9-]{0,62}\.[a-z0-9][a-z0-9-]{3,62}\.(?:lab|internal|local|home|lan)\b|\b[a-z][a-z0-9-]{3,62}\.(?:lab|internal|local|home|lan)\b/gi },
  { name: "pem-private-key", re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g },
  // AKIA is a long-term key, ASIA a temporary (STS) one. Both are 20 chars,
  // which is under the entropy rule's 40-char floor, so if this rule misses
  // the prefix nothing else catches it.
  { name: "aws-access-key-id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: "openai-style-key", re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  // The optional closing quote before the separator is load-bearing: \s*[=:]
  // cannot cross one, so {"token":"hunter2abcdef"} and {"api_key": "..."}
  // scored zero — and that is exactly the serialization Astro emits for
  // island props and for any dist/*.json.
  // Two forms. A QUOTED value runs to its closing quote, so punctuation inside
  // it cannot end the match early. An UNQUOTED value stops only at whitespace,
  // quotes or a tag boundary. The old class was [A-Za-z0-9/+_-], which halted at
  // the first symbol: `password: P@ssw0rd!x` matched just "P", failed the
  // length floor, and reported clean — and punctuation is exactly what a strong
  // password has. The unquoted class still stops at STRUCTURAL delimiters
  // (, ; : {} () []), because a minified bundle's `password:!0,range:!0,...`
  // input-type map is not a value and matching it made the scan red on a clean
  // build. That is a rule that was wrong, not a false positive to baseline: the
  // baseline is exact-match, and a minified fragment changes every rebuild.
  { name: "credential-assignment", re: /\b(?:api[_-]?key|secret|token|password|passwd)["']?\s*[=:]\s*(?:(["'])(?:(?!\1)[^\n]){6,}\1|[^\s"'<>,;:{}()\[\]]{8,})/gi },
  // Colon, hyphen and Cisco dotted-triple. The rule advertises "MAC address";
  // colon-only quietly meant "MAC addresses written one particular way".
  { name: "mac-address", re: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/gi },
  // Base64/hex alphabet only (no - or _) plus mixed case plus a digit. The
  // permissive form matches CSS custom properties and asset paths; this one
  // scores zero against the real build, which is why the baseline is empty.
  // No ={0,2} for the base64 padding: the trailing \b cannot follow an `=`,
  // so the engine backtracked to zero `=` every time and the quantifier was
  // dead. Dropped rather than swapped for a (?![A-Za-z0-9+/]) lookahead —
  // padding is not what detects the run, the 40-character body is, and
  // replacing the anchor widens the rule against a build nobody has measured.
  // Lookarounds on the rule's OWN alphabet, not \b. Underscore is a word
  // character, so `opaque_<60 chars>` matched neither boundary and a long
  // opaque value sitting next to an underscore was invisible.
  { name: "high-entropy-run", re: /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}(?![A-Za-z0-9+/])/g },
];

const isHighEntropy = (s) => /[a-z]/.test(s) && /[A-Z]/.test(s) && /[0-9]/.test(s);

/** @returns {{files: string[], unclassified: string[], binaries: string[]}} */
function walk(dir) {
  const files = [];
  const unclassified = [];
  // Recognised-binary files are not opened, but their NAMES still ship in the
  // public URL, so they are collected rather than dropped.
  const binaries = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      const sub = walk(full);
      files.push(...sub.files);
      unclassified.push(...sub.unclassified);
      binaries.push(...sub.binaries);
      continue;
    }
    // extname(".env") is "" — a dotfile's whole name IS its extension for our
    // purposes, and ".env" is in SCANNED_EXT precisely because one dropped into
    // public/ is exactly what we want to read. Without this it landed in
    // `unclassified` and exited 2: fail-closed, but for the wrong reason, and
    // confusing to whoever put it there.
    const lower = e.name.toLowerCase();
    const ext = extname(lower) || (lower.startsWith(".") ? lower : "");
    if (SCANNED_EXT.has(ext)) files.push(full);
    else if (KNOWN_BINARY_EXT.has(ext)) binaries.push(full);
    else unclassified.push(full);
  }
  return { files, unclassified, binaries };
}

/**
 * The text a READER receives, not the markup that carries it.
 *
 * `<code>password</code>: <code>hunter2abcdef</code>` renders as a plain
 * credential assignment and every rule here misses it, because the regex sees
 * the tags in between. That is the same failure as the `data:` URI exclusion
 * this scanner already dropped: the scanner examining a different
 * representation than the person looking at the page.
 *
 * Scripts and styles are dropped rather than flattened — their content is code,
 * already scanned in the raw pass, and inlining it here would only duplicate
 * findings.
 */
function decodeEntities(text) {
  return text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    // Named references for the punctuation our rules key on. Node ships no HTML
    // entity table and this repo takes no dependency, so this is the targeted
    // set rather than all ~2200: a full decoder is the right answer the day a
    // dependency is acceptable. Documented as a known limit in README.
    .replace(/&colon;/gi, ":")
    .replace(/&period;|&dot;/gi, ".")
    .replace(/&commat;/gi, "@")
    .replace(/&lowbar;/gi, "_")
    .replace(/&sol;/gi, "/")
    .replace(/&num;/gi, "#")
    .replace(/&equals;/gi, "=")
    .replace(/&excl;/gi, "!")
    .replace(/&hyphen;|&dash;/gi, "-")
    .replace(/&plus;/gi, "+")
    // BOTH numeric forms. Decimal alone left `password&#x3a; secret` invisible
    // while `password&#58; secret` was caught — the same string, one encoding
    // apart, and the browser renders them identically.
    .replace(/&#(\d+);?/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\s+/g, " ");
}

function renderedText(html, sep = " ") {
  return decodeEntities(
    html
      .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<[^>]+>/g, sep),
  );
}

function applyRules(file, text, into, seen) {
  for (const { name, re } of RULES) {
    for (const m of text.matchAll(re)) {
      if (name === "high-entropy-run" && !isHighEntropy(m[0])) continue;
      // Whitespace-insensitive: the same secret reached through different
      // normalizations differs only in the spaces the tag substitution left
      // behind ("password : x" vs "password: x"), and reporting one leak
      // four times teaches people to skim the output.
      const key = `${name}\u0000${m[0].replace(/\s+/g, "")}`;
      if (seen.has(key)) continue;
      seen.add(key);
      into.push({ file, rule: name, match: m[0] });
    }
  }
}

/**
 * Read a text file the way a browser or editor would.
 *
 * readFileSync(..., "utf8") on a UTF-16 file yields interleaved NULs, so a
 * BOM-marked file containing `password: secret` scanned clean while every
 * other tool on the machine displayed it plainly.
 */
function readText(full) {
  const buf = readFileSync(full);
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.toString("utf16le");
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) return buf.swap16().toString("utf16le");
  return buf.toString("utf8").replace(/^\ufeff/, "");
}

export function scanText(file, text, { html = HTML_EXT.test(file) } = {}) {
  const findings = [];
  const seen = new Set();

  // 1. Raw, entity-decoded. Decoding matters here and not only in the rendered
  //    pass: `<div data-config="password&#58; secret">` hides the token in an
  //    ATTRIBUTE, which the rendered pass deletes with the whole tag.
  applyRules(file, text, findings, seen);
  applyRules(file, decodeEntities(text), findings, seen);

  if (html) {
    // 2. Rendered with tags as SPACE — the reader's text, without joining
    //    words that sit in separate blocks.
    applyRules(file, renderedText(text, " "), findings, seen);
    // 3. Rendered with tags as NOTHING — adjacency. `<span>AKIA</span><span>ABC…`
    //    renders as one key, and pass 2 breaks it with the space it inserts.
    //    Both are needed: neither normalization sees what the other does.
    applyRules(file, renderedText(text, ""), findings, seen);
  }
  return findings;
}

export function run(distDir = DEFAULT_DIST, baselinePath = DEFAULT_BASELINE) {
  if (!existsSync(distDir)) {
    return { code: 2, findings: [], scanned: 0,
      reason: `${distDir} does not exist. Run \`npm run build\` first.` };
  }
  // D11 distinguishes 1 from 2 so nobody reads "the scan could not run" as
  // "the scan found something". Every structural failure below therefore
  // RETURNS 2 rather than throwing: an uncaught throw exits 1 with a stack
  // trace, which reports a broken scanner as a leak.
  let files, unclassified, binaries;
  try {
    ({ files, unclassified, binaries } = walk(distDir));
  } catch (err) {
    // A `dist` path that is a file, not a directory, lands here as ENOTDIR.
    return { code: 2, findings: [], scanned: 0,
      reason: `cannot walk ${distDir}: ${err.message}` };
  }
  // Checked before "empty" and "no HTML": an unclassified type is the most
  // actionable of the three failures, and reporting it first tells the author
  // exactly which line of this file to edit.
  if (unclassified.length > 0) {
    const names = unclassified.map((f) => relative(distDir, f)).sort();
    const shown = names.slice(0, 5).join(", ");
    return { code: 2, findings: [], scanned: 0,
      reason: `${names.length} file(s) of unclassified type under ${distDir}: `
        + `${shown}${names.length > 5 ? ", …" : ""}. Add each extension to `
        + `SCANNED_EXT or KNOWN_BINARY_EXT in tools/scan-dist.mjs — an `
        + `unopened file is an unscanned file.` };
  }
  if (files.length === 0) {
    return { code: 2, findings: [], scanned: 0,
      reason: `no scannable files under ${distDir}.` };
  }
  if (!files.some((f) => HTML_EXT.test(f))) {
    return { code: 2, findings: [], scanned: files.length,
      reason: `no built HTML under ${distDir}; a scan over no pages reports green.` };
  }
  let baseline;
  try {
    const raw = existsSync(baselinePath)
      ? JSON.parse(readFileSync(baselinePath, "utf8")) : [];
    // Each entry is `rule|file|match` — SCOPED, not a bare string. A match-only
    // baseline is a repository-wide allowlist: approving a dependency's
    // 192.168.1.1 would also permit an author to publish that same real gateway
    // address on a page, silently, forever. Bare strings are still accepted so
    // an older baseline keeps loading, and are treated as match-only with that
    // weakness made explicit here rather than hidden.
    if (!Array.isArray(raw) || raw.some((x) => typeof x !== "string")) {
      return { code: 2, findings: [], scanned: files.length,
        reason: `${baselinePath} must be a JSON array of "rule|file|match" strings.` };
    }
    baseline = new Set(raw);
  } catch (err) {
    return { code: 2, findings: [], scanned: files.length,
      reason: `cannot read ${baselinePath}: ${err.message}` };
  }
  const suppressed = (x) =>
    baseline.has(`${x.rule}|${x.file}|${x.match}`) || baseline.has(x.match);

  const findings = [];
  // Paths first: a secret can be the NAME rather than the content. A screenshot
  // filed under a hostname-shaped directory, or AKIA….html, is exposed in the
  // public URL while its bytes are innocent — and a binary file's bytes are
  // never opened at all, so its path is the only thing there is to check.
  for (const f of [...files, ...binaries]) {
    const rel = relative(distDir, f);
    findings.push(...scanText(`${rel} (path)`, rel, { html: false })
      .filter((x) => !suppressed(x)));
  }
  for (const f of files) {
    let text;
    try {
      text = readText(f);
    } catch (err) {
      return { code: 2, findings: [], scanned: files.length,
        reason: `cannot read ${relative(distDir, f)}: ${err.message}` };
    }
    findings.push(...scanText(relative(distDir, f), text).filter((x) => !suppressed(x)));
  }
  return { code: findings.length > 0 ? 1 : 0, findings, scanned: files.length, reason: null };
}

export function main(argv = process.argv.slice(2)) {
  const { code, findings, scanned, reason } = run(
    argv[0] ?? DEFAULT_DIST, argv[1] ?? DEFAULT_BASELINE);
  if (code === 2) {
    console.error(`scan-dist: FAIL-CLOSED — ${reason}`);
  } else if (code === 1) {
    console.error(`scan-dist: ${findings.length} secret-shaped string(s):`);
    // The match is NOT printed by default. This scan runs in GitHub Actions on a
    // PUBLIC repository, so echoing a real secret here would copy it into a
    // world-readable log — amplifying the exposure the scan exists to prevent.
    // The rule and the file are enough to find it; SCAN_SHOW_MATCHES=1 prints
    // the literal text locally, which is how a baseline entry gets written.
    const reveal = process.env.SCAN_SHOW_MATCHES === "1";
    for (const f of findings) {
      const shown = reveal ? f.match : `<redacted ${f.match.length} chars>`;
      console.error(`  ${f.file}: [${f.rule}] ${shown}`);
    }
    if (!reveal) {
      console.error("  (matches redacted; re-run locally with SCAN_SHOW_MATCHES=1 to see them)");
    }
  } else {
    console.log(`scan-dist: clean — ${scanned} file(s), ${RULES.length} rules, 0 findings.`);
  }
  return code;
}

// realpathSync matters: on macOS /tmp is a symlink, so comparing import.meta.url
// (already a real path) against argv[1] as given silently skips the CLI block.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  process.exit(main());
}
