# Report

> **Status:** implemented 2026-10-28 (`reporting/`). `collect` writes a report for every run
> after Stage 4; `kitsunox report <run_id>` rewrites one.

## Purpose

Turn Stage 4's decisions into something a reviewer can act on quickly: a queue ordered by
score, and for each version what changed, why it was reported, the evidence, and where to look.

## Usage

```sh
uv run kitsunox report <run_id>     # after `correlate`; writes data/runs/<run_id>/report/
```

## Output (`data/runs/<run_id>/report/`)

| File | What |
|---|---|
| `report.json` | Canonical (roadmap decision 4). Run summary plus one entry per reported version, highest score first |
| `index.md` | The review queue: rank, package, score, severity, top rules, watched |
| `entries/NNNN-<package>@<version>.md` | One page per entry |

An entry holds:

- **What changed:** version and previous version, publish time, publisher, popularity.
- **Why:** the Stage 4 decision, the score broken down by rule (each rule counted once, with
  how many findings it had), and every finding grouped by stage and rule, with evidence.
- **Where to look:** npm page, the npm file browser, a diff against the previous version
  (npmdiff.dev), the repository, and the repository at the commit Stage 4 compared against.

Manifests are not copied into the report (they are large; the findings quote what matters).

## Properties

- **Deterministic.** Built only from `correlate.jsonl`, `correlate.json` and the run manifest,
  sorted, no clock: the same run gives the same bytes (`test_publish_is_byte_stable...`).
  Pages from an earlier render are removed, so the directory always matches `report.json`.
- **Safe to render.** Everything from a package is untrusted and may be crafted to break the
  page: backticks to close a code block, `|` to forge a table cell, HTML, `javascript:` links,
  bidirectional-override characters that make text read differently from what it is.
  - code and evidence go in fences longer than any backtick run inside them;
  - inline text is flattened to one line, with HTML and Markdown punctuation escaped and
    control/bidi characters dropped;
  - links are emitted only for `https://` URLs without spaces, quotes or angle brackets; and
    the repository link only when the URL is `https://` (only GitHub URLs are normalised);
  - page file names are sanitised (`../../etc/passwd` becomes `0001-.._.._etc_passwd...`
    with no path separators).

## First look (2026-10-28)

A preview on the hour `20261028T031447Z-npm` (3,731 versions): 24 to review (0.6%), 10 with a
HIGH finding. It surfaced two noise sources, both fixed or recorded:

- `@types/*` packages republished by DefinitelyTyped's bot set off
  `npm.combination.revived-with-new-dependency` (4 in that hour); exempted when the `types`
  account published both versions.
- `static.exfil-endpoint` v2 still matches placeholder webhooks in documentation
  (`discord.com/api/webhooks/123/abc` in `@waffo/pancake-ts`'s README and bundled JSDoc). Left
  for Stage 2 tuning.

## Not yet

- A cross-run queue (today each run has its own report).
- HTML and the local web viewer (Phase 11), from the same `report.json`.
