# lab-architecture

The **Publish** boundary of the Patchoutech home lab: a static white-paper site
that explains how the lab is structured and how an AI agent is allowed to
operate it.

Live at **<https://agentops.patchoutech.com>**.

> Allowed to act. Unable to overreach.

## What this repository is

The lab is split along a single seam, one repository per job:

| Boundary | Repository | Job |
| --- | --- | --- |
| Describe | `Home.servers` | `inventory.yaml` is the canonical record; reference docs and the architecture diagram are generated from it. Touches no infrastructure, holds no credentials. |
| Operate | `Home.servers/agent-ops` | The only component that reaches live infrastructure, under a capability registry, an approval policy, and an append-only operator ledger. |
| Publish | **this repo** | The public, human-readable account of the other two. |

This site is the third boundary. It is **hand-authored prose**, not a generated
projection of the lab: no `inventory.yaml` data, no hostnames, no addresses and
no credentials are exported into it, and no build step here reads anything from
the lab. The explorer's physical graph is a deliberately generic stand-in
(`src/data/graph.ts` says so at the top). That is why no lab data can appear
here **by ingestion** — not because a filter removes it, but because it was never
imported.

That is a claim about the pipeline and not a guarantee about the output. The
build compiles what it is given, so an author who types a real hostname,
address or credential into a page can still publish it. That path is covered by
the [output tripwire](#the-output-tripwire), which scans the built `dist/` on
every build that can reach the public — the pull-request check and the deploy —
and fails on anything secret-shaped. A local `npm run build` does not invoke it;
the gate is on the path that publishes. It catches
secret-*shaped* strings; it is not a guarantee against every possible mistake.

The two mechanisms that would let this site ever carry real lab data are in
different states, and the pages say which one wherever they discuss that
pipeline. The output tripwire is **built**, and it runs here. The inventory-fed
allowlist projection is built inside the Describe boundary and is **not wired**
to this site: nothing carries its artifact here, and no build step in this
repository reads anything from the lab.

## Running it locally

Node **22.12.0** (see `.nvmrc`). One command per line; nothing here needs
chaining.

```sh
npm ci
npm run build    # emits dist/
npm run scan     # the output tripwire over dist/
npm test         # node:test assertions over the built dist/
```

Both `npm run scan` and `npm test` read `dist/`, so run `npm run build` first.

For the dev server, `AGENTS.md` requires background mode — `npm run dev` runs
`astro dev` in the foreground and blocks the shell:

```sh
npx astro dev --background
npx astro dev status
npx astro dev logs
npx astro dev stop
```

If you invoke npm from outside the project root, use `npm --prefix
/path/to/lab-architecture run build` — the scripts resolve their paths from the
project root, not the working directory.

## The output tripwire

`npm run scan` runs `tools/scan-dist.mjs` over the built `dist/`, and both
workflows run it after the build and before anything else that consumes the
build — in `deploy.yml` it runs before the Cloudflare credentials are so much
as read. It knows nothing about the lab: every rule is a self-contained pattern
for a *shape* (RFC 1918 address, private-use FQDN, PEM header, AWS/GitHub/
OpenAI-style key, credential assignment, MAC address, long high-entropy run).
Handing this repository the inventory to check against would publish the
secrets it exists to keep out.

It scans **every** file type in `dist/` except a short, explicit list of
known-binary extensions. A file whose extension is on neither list stops the
build: an unopened file is an unscanned file.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Clean. Nothing secret-shaped in the build. |
| 1 | Findings. Each is printed as `path: [rule] <redacted N chars>`. The matched text is **not** echoed: this scan runs in Actions on a public repository, and printing a real secret there would copy it into a world-readable log. Set `SCAN_SHOW_MATCHES=1` locally to reveal it — which is how a baseline entry gets written, since the baseline is exact-match. |
| 2 | Structural failure — missing/empty `dist/`, no built HTML, an unclassified file type, an unreadable or malformed baseline. The scan could not do its job, which is not the same as finding nothing. |

Exit 2 is deliberately not exit 1, so "the scan is broken" is never read as
"the scan found nothing".

**A real finding is removed from the source.** Never from the scan. There is
exactly one sanctioned way to silence a false positive: add the offending
string, verbatim and in full, as one entry in `tools/scan-baseline.json`.

```jsonc
["Ab3xY9kQ...the exact matched string..."]
```

Never a path exclusion, never a directory exclusion, never a narrowed rule to
make one file pass. An exact-match entry suppresses that one string and
nothing else, so the next dependency bump that emits a *different*
secret-shaped string still reds the build. A path or glob exclusion silently
covers everything that file will ever contain, including the leak it does not
have yet. That doctrine is the only reason this mechanism survives a
dependency bump; the baseline is empty today and every line ever added to it
should be justified in the commit that adds it.

## How it deploys

Push to `main` → `.github/workflows/deploy.yml` builds the site and deploys
`dist/` to the Cloudflare Pages project **`patchoutech-architecture`**, which
serves the custom domain `agentops.patchoutech.com`.

Two repository secrets drive the deploy step:

- `CLOUDFLARE_API_TOKEN` — scoped token with *Account → Cloudflare Pages → Edit*
- `CLOUDFLARE_ACCOUNT_ID`

Both are set. If the token is ever absent the workflow still builds (as CI) and
skips only the deploy step, so a missing secret shows up as a skipped deploy
rather than a red build.

## Layout

```text
src/pages/       one Astro page per section; the prose lives here
src/layouts/     Layout (shell + nav) and ContentPage (kicker/headline/stand)
src/components/  Callout, Chips, PullQuote, StatRow, PageNav
src/components/explorer/  the React Flow island (client-hydrated, inert)
src/data/graph.ts         the explorer's hand-authored graph
src/data/nav.ts           the nav model and reading order
tests/           build assertions run against dist/
tools/scan-dist.mjs       the output tripwire
tools/scan-baseline.json  exact-match false-positive suppressions (empty)
```

## Editing rules

Every factual claim on this site is checked against the live estate before it
ships. Two rules follow from that:

1. **Do not strengthen a claim past what the estate does.** A mechanism is
   designed, or built, or built-and-wired-to-this-site, and the page must say
   which. "Built" somewhere else is not "wired" here.
2. **Re-verify before you re-word.** The estate moves; a claim that was true in
   July can be false in September, and the reverse happens just as often.

The last claim-by-claim pass ran **2026-09-04**.
