# Report

> **Status:** implemented 2026-10-28 (`reporting/`). `collect` writes a report for every run
> after Stage 4; `kitsunox report <run_id>` rewrites one. Since 2026-10-29 it also rebuilds a
> **review queue** across runs after each tick (`kitsunox queue`). Since 2026-10-30 a run that
> Stage 5 has rendered is reported from `sandbox.jsonl`: Stage 5's findings (group "Stage 5:
> sandbox") count in the score, and the index has a Stage 5 line. The report is rebuilt after
> every live Stage 5 call ([stages/sandbox.md](sandbox.md#usage)).

## Purpose

Turn Stage 4's decisions into something a reviewer can act on quickly: a queue ordered by
score, and for each version what changed, why it was reported, the evidence, and where to look.

## Usage

```sh
uv run kitsunox report <run_id>     # after `correlate`; writes data/runs/<run_id>/report/
uv run kitsunox queue [--days 7]    # every report of the last DAYS, by package: data/queue/
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
  - inline text is flattened to one line, with HTML and Markdown punctuation escaped;
  - hidden characters are dropped from text and code alike and counted, with a bold
    "[N hidden characters removed]" after the text or block. The set is by Unicode category
    (`util/text.py`): controls other than tab and newline, format characters (bidi, zero-width,
    tags), private use, surrogates, line/paragraph separators, and the other default-ignorable
    characters such as variation selectors and Hangul fillers. Real npm malware hid payloads in
    variation selectors (GlassWorm) and private-use characters (os-info-checker-es6). The
    carriage return of a CRLF line ending and a byte order mark at the very start are
    dropped without being counted, so snippets from Windows or BOM-prefixed files get no
    marker; a lone carriage return or a BOM elsewhere still counts;
  - links are emitted only for plain ASCII `https://` URLs with a host name and no user info
    (`https://www.npmjs.com@evil.example/` is not linked), quotes, spaces, controls or
    backslashes (`util.text.safe_url`, shared with the viewer). Any other URL is shown as an
    inline code span marked "(not linked)", not as text: renderers that autolink bare URLs,
    `www.` hosts and e-mail addresses (GitHub, linkify previews) never do so inside code
    (`test_rejected_urls_cannot_be_autolinked`). URLs *quoted inside explanations* are still
    plain escaped text, so such a renderer may autolink them: a known limit; and
    the repository link only when the URL is `https://` (only GitHub URLs are normalised);
  - page file names are sanitised (`../../etc/passwd` becomes `0001-.._.._etc_passwd...`
    with no path separators).

## Review queue (`data/queue/`)

A run's report lists *versions*. Read across runs, that has two problems: a package that
releases often fills the list (27 `@lightdash/cli` versions in one day were 27 entries), and
chained runs overlap by 15 minutes, so a version can be reported twice. `reporting/queue.py`
reads every `report/report.json` whose `as_of` is within `--days` (default 7, the run retention)
of the newest one and writes:

| File | What |
|---|---|
| `queue.json` | Canonical `Queue`: the runs read, unreadable reports left out, and one `QueueEntry` per package |
| `index.md` | The queue as a table: rank, package, score, severity, versions (each linking to its page in the run that reported it), rules with the number of versions they fired on |

- **One entry per package.** Its score and severity are the highest among its versions. Its
  versions are listed newest first. Each rule counts how many of its reported versions it
  fired on.
- **Each version once**, from its *strongest* sighting (severity, then score; the earliest run
  on a tie). An overlapping later run may have known more, for example a tag pushed since or a
  new label set, and a missed attack costs more than a false positive. Evaluation datasets keep
  the earliest sighting instead: that choice is about labels.
- **Ordered** by score, then severity, then name.
- **Deterministic:** the window ends at the newest report's `as_of`, not the clock. The same
  reports give the same bytes (`test_queue_is_byte_stable`).
- **Untrusted text** is escaped as in the run reports (`test_untrusted_names_cannot_break_the_table`).
- **Cost follows the window, not the history.** Runs and their reports outlive pruning, so
  the window is chosen from each run's small `manifest.json`. Only the reports inside it are
  read, one at a time, and only a few fields of each version are kept.
- **An unreadable report** in the window (damaged, or written with another schema version) is
  listed in `skipped` and left out. It doesn't stop the queue.
- `collect` rebuilds the queue after prune (best-effort), so pruned runs drop out after
  `--days`. Their report pages stay, so the links keep working.
- **Confirmed since** ([decision 0016](../decisions/0016-after-the-fact-confirmations.md)):
  each version carries the registry takedowns published after it (npm's `0.0.1-security`
  holder, found in the runs' feeds by `collect` and kept in `data/takedowns/npm.json`; also
  `kitsunox takedowns`) and the OSV `MAL-` records covering it, as of the queue's `as_of`.
  `confirmed` lists the versions with a verdict that were confirmed since, benign first; the
  index counts them per verdict and lists the benign and inconclusive ones to review again,
  and its table gets a "Confirmed since" column. A flag only: no score changes
  (`test_versions_confirmed_since_are_flagged_never_scored`).
- A run whose Stages 1-4 finished but whose report is incomplete is caught up "from the
  report" on the next tick, without redoing Stage 4. Incomplete means `report.json` or
  `index.md` (written last) is missing, or `report.json` doesn't load
  (`test_a_missing_report_alone_is_redone`). Version links are checked to resolve to the pages
  the run wrote (`test_every_version_link_resolves`).

## Re-scoring (`kitsunox rescore`, 2026-10-30)

A run's report is written once, by the rules of its tick, and stays in the queue until the run
is pruned. `kitsunox rescore RUN... | --queued [--skip-rescored]` runs Stages 1-4 and the report
again with the current rules (`collect.rescore_run`):

- **From the run's recorded inputs:** its `changes.jsonl`, and its Stage 2 and 4 snapshots as
  seeds, so every response they recorded (tarballs, refs, archives, packuments) is served as it
  was then; only requests the current rules newly need (a version Stage 1 now routes to Stage
  2) go to the network, and are recorded too.
- **The tick's outputs are kept** under `before-rescore/` (the first re-score only), and
  `rescore.json` says when and how many versions it reported before and after.
- **Verdicts carry over** (they are by version), and the queue is rebuilt after each run.
- **The lock is taken one run at a time**, so a scheduled tick can run between two runs; a
  run busy with a tick stops the command (exit 3), and `--skip-rescored` resumes.

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

- (Done 2026-10-30: reviewer verdicts, per version, in the viewer and `kitsunox verdict`; see
  [viewer.md](../viewer.md#reviewing) and decision 0015.)
- Exported HTML files. The local web viewer ([viewer.md](../viewer.md), `kitsunox view`) renders
  the same `report.json` and `queue.json` in a browser.
