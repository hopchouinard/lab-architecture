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

That is a claim about the pipeline and not a guarantee about the output. An
author who types a real hostname, address or credential into a page ships it:
the build compiles what it is given and nothing scans the result. Covering that
path is what the tripwire below is for.

The inventory-fed allowlist projection and the output tripwire that would let
this site carry real lab data are **designed and not built**. The site's pages
say so wherever they discuss that pipeline.

## Running it locally

Node **22.12.0** (see `.nvmrc`). One command per line; nothing here needs
chaining.

```sh
npm ci
npm run build    # emits dist/
npm test         # node:test assertions over the built dist/
```

`npm test` reads `dist/`, so run `npm run build` before it.

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
```

## Editing rules

Every factual claim on this site is checked against the live estate before it
ships. Two rules follow from that:

1. **Do not strengthen a claim past what the estate does.** If a mechanism is
   designed but not built, the page must say which.
2. **Re-verify before you re-word.** The estate moves; a claim that was true in
   July can be false in September, and the reverse happens just as often.

The last claim-by-claim pass ran **2026-09-04**.
