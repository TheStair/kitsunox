# Local web viewer

> **Status:** implemented 2026-10-29 (`src/kitsunox/web/`, roadmap Phase 11). It reads the
> same `report.json` and `queue.json` that the Markdown views come from, and since 2026-10-30
> records reviewers' verdicts ([decision 0015](decisions/0015-reviewer-verdicts.md)). No new
> dependencies: the server is the standard library's `http.server`. Since 2026-11-09 it also
> shows live evaluation's results (`/results`, `/results/sample`) and opens on a dashboard;
> the review queue moved from `/` to `/queue`.

## Purpose

The Markdown queue and pages (see [stages/report.md](stages/report.md)) work in an editor, but
moving between the queue, a run and one version's evidence means opening files by hand. The
viewer serves the same data as linked pages in a browser on the collection machine, and lets
the reviewer record what each version is. It also shows the live evaluation's confusion
matrices, misses, trend and review sample ([evaluation.md](evaluation.md#live-evaluation-phase-9)),
read from the same files `kitsunox live eval` writes. It never fetches and never runs package
code; the only thing it writes is the verdict log.

## Reviewing

Each version in the queue has buttons for the four verdicts
([decision 0015](decisions/0015-reviewer-verdicts.md), addendum "four categories"):
**Malicious**, **Unwanted**, **Benign**, and **Unverified: why?**, which opens (a `<details>`,
no script) one button per reason: *code gone*, *remote payload*, *obfuscated*, *binary
payload*. An unverified verdict can't be sent without its reason. The entry page has the same
buttons with a note, the version's verdict and its history, and **Back to
the queue** once it has one. A verdict takes the version out of the queue at once (and out of
`queue.json` and `index.md` on the next tick); a package with no version left disappears from
it. The header links each verdict's page (`/verdicts/malicious`, `/verdicts/unwanted`,
`/verdicts/benign`, `/verdicts/unverified`): every version with that verdict now, most recent first, with its score,
severity, rules, publisher, the reviewer, the time and the note, and a link to the entry while
its run is kept; an unverified version shows its reason as a tag. The queue page opens with the
tally ("Verified malicious: N", then every category, unverified split by reason), and so does
the daily Discord summary. A new release of a reviewed package comes back to the queue: verdicts are
per version.

A queued version that looks like one you cleared (same package, publisher and rules as a
version with a benign verdict) says "like 1.2.3, which you cleared"; it stays in the queue.

A version that npm has since removed, or that an OSV `MAL-` record covers, is marked
**Confirmed since** on the queue, verdict and entry pages, and the queue page lists benign,
unwanted or unverified verdicts confirmed since under "Review these again" (a check, never part of a
score; [decision 0016](decisions/0016-after-the-fact-confirmations.md)). The flags come from
`queue.json`, so they appear after the next tick or `kitsunox queue`.

The log is `data/verdicts/npm.jsonl` (`reporting.verdicts`), append-only: the last record for a
version is its verdict, and the whole history is kept. Each record copies the entry as reviewed,
so the verdict pages outlive the run's 7 days. From a shell, `kitsunox verdict <run_id> <rank>
malicious|unwanted|benign|reopened [--note TEXT] [--by NAME] [--probe]`, or `... unverified
--reason gone|remote|obfuscated|binary`, records the same thing (an analyst records under its
own name, so the owner can tell its verdicts from theirs and override them), and `kitsunox
verdicts [KIND]` lists them with the tally. `--reason` is required for `unverified` and refused
for anything else. Records written before 2026-11-08 as `inconclusive` still load, shown as
unverified with "no reason (was inconclusive)" until a newer record reclassifies them.

### What counts as malicious

A verdict follows what the code does, not what it says about itself. Security researchers
publish dependency-confusion and bug-bounty probes, often in bulk, and many carry an
"authorized test" notice; malware can carry the same notice, and nothing checks it. So
(owner policy 2026-11-01):

- **Malicious** if, at install or import, anything identifying leaves the machine (user name,
  hostname, working directory, home directory, environment, a DNS or HTTP beacon to a host the
  author controls), or code is fetched and run. The claimed authorization doesn't change this.
  npm and OSV agree: every probe npm removed after we reported it sent machine data out.
- **Benign** if it only does something local with no network: opens calc.exe, writes a marker
  file in the package or project.
- **Unwanted** when the behaviour is seen in full and is covert or intrusive but not harmful
  enough to call malware, like an antivirus "PUA": an install-time beacon that carries only a
  marker (no hostname, user, path, environment or credentials), or a WhatsApp Baileys fork that
  auto-follows, joins or mutes channels, hidden or disclosed (owner, 2026-11-08; malicious only
  with evidence that the follow spreads malware, benign when the follow is opt-in).
- **Unverified** when we couldn't confirm what it does, with the reason: `gone` (unpublished or
  never captured), `remote` (the payload comes from a repository or URL we couldn't see),
  `obfuscated` (we couldn't decode it; it waits for the sandbox) or `binary` (an unexplained
  native or binary payload). Code that is staged but not yet armed (it collects data but only
  sends it to 127.0.0.1) was "inconclusive" before; it fits none of the four definitions
  cleanly and is left to the owner case by case (flagged in the 2026-11-08 reclassification).

Tick **Research probe** on the entry page (or the package form, or `kitsunox verdict ...
--probe`) for any version that is a researcher's probe or PoC, whatever its verdict. The tag
leaves the verdict as it is; the queue page, the `kitsunox verdicts` tally and the daily Discord
summary count tagged versions apart, so probes can be told from commodity malware while both
stay detected.

## Running it

```sh
uv run kitsunox view                      # http://127.0.0.1:8000/ for ./data
uv run kitsunox view --port 8080 --data-dir data-demo
uv run kitsunox view --host 192.168.1.5 --allow-remote   # one specific address (see below)
```

Options: `--data-dir` (default `data`), `--host` (default `127.0.0.1`), `--port` (default
8000; 0 picks a free port) and `--allow-remote`. Ctrl-C stops it.

From another machine, for example a laptop browsing the collection VM, use an SSH tunnel and
keep the viewer on loopback:

```sh
ssh -L 8000:127.0.0.1:8000 <vm>           # then open http://localhost:8000/ on the laptop
```

The tunnel may use any local port: the Host check accepts loopback names on any port.

In code, `kitsunox.web.serve(data_dir, host="127.0.0.1", port=8000, *, allow_remote=False,
announce=None)` blocks until Ctrl-C. `announce` gets the URL once the socket is bound (so port
0, "any free port", can be reported). It raises `RemoteBindRefusedError` for a host it may not
bind, and `OSError` if the port is taken. `make_server(...)` returns the bound server without
serving it, for tests.

### Listening on another address

The viewer has no login and no TLS, so by default it refuses any host that isn't loopback
(`127.0.0.0/8`, `::1`, `localhost`). With `allow_remote=True` (`--allow-remote` in the CLI) it
binds one **specific** address, such as a VM's private IP. It still refuses `0.0.0.0`, `::` and
the empty host ("every interface"): the Host check needs to know the one name it is reached by.

The host is checked twice: as given, and as the address the socket actually bound. Names such
as `0`, `0.0` or `0.0.0` aren't IP addresses as written but resolve to `0.0.0.0`, and
`localhost` could be mapped to a LAN address in `/etc/hosts`; the bound-address check catches
both and closes the socket before anything is served. Anyone who can reach a remote address
can read every report, so prefer the SSH tunnel.

## Pages

| Path | What |
|---|---|
| `/` | The dashboard: the newest live report's headline (flag-worthy recall and precision of window `all`, with their Wilson intervals and k of n) with the strict and OSV-truth matrices beside it, the number of misses, the verdict tally, the queue's size, the newest sample day's progress, and the newest run (as of, versions, reported). How old the labels and the queue are is measured against the newest run's `as_of`, not the clock. Until 2026-11-09 `/` was the queue; old bookmarks land here, one click from it. |
| `/queue` | The review queue (`data/queue/queue.json`, without versions that have a verdict now): the verdict tally, then packages ranked by score, then severity, then name. Each row has the score, severity, every reported version (newest first, each linking to its entry in the run that reported it most strongly, with verdict buttons), the rules with the number of versions they fired on, watched, and last publish time. Unreadable reports the queue left out are listed with links to their runs. |
| `/results` | The newest live report (`data/eval/live/reports/live-*.json`); see [Results](#results). |
| `/results/<dataset>` | Any live report on disk, by its dataset id (`live-YYYYMMDDTHHMMSSZ`, the label set's id). |
| `/results/sample` | The newest day's label-blind review sample (`data/eval/live/sample/<day>.json`); see [Results](#results). |
| `/results/sample/<day>` | One day's sample (`YYYY-MM-DD`). |
| `/verdicts` | The verdict tally and a link to each category. |
| `/verdicts/<kind>` | Every version whose verdict is `malicious`, `unwanted`, `benign` or `unverified` now (see [Reviewing](#reviewing)). |
| `POST /verdict` | Records a verdict from a form, then redirects back (303): to the page that sent it, `/queue` for the queue's forms and for a missing or foreign `back`. See the security table. |
| `/runs` | Runs with a `report/report.json`, newest first, 50 per page (`/runs/page/N`): release window, versions analysed, how many to review, counts by severity, and a note when Stage 4 couldn't compare versions with their repository because of the network. |
| `/runs/<run_id>` | One run's report: summary, the network warning, the versions to review (rank, package, score, severity, top three rules, watched), and Stage 4's settings (`correlate.json`) in a collapsed block. |
| `/runs/<run_id>/entries/<rank>` | One version: score and Stage 4's reason; what changed (previous version, publish time and publisher, popularity); where to look (npm, the file browser, npmdiff, the repository and the repository at the compared commit); how the score adds up (each rule once, with its weight and number of findings, and the total); and every finding grouped by stage and rule, with its explanation and evidence (file and lines, the snippet, before/after side by side). Links go to the previous and next entries. |
| `/static/style.css` | The one stylesheet. |

Anything else is a 404. The header links Dashboard, Queue, Results, Sample, Runs and Verdicts.

- **No queue yet**, **no run with a report**, **no live evaluation** ("run `kitsunox live
  eval`") and **no review sample** are short messages, not errors.
- **An unreadable file** (damaged, not JSON, written with another schema version, or with
  fields this build doesn't know) is an error box naming the file and the kind of problem
  (for a schema mismatch, which version it has and which this build reads). Pydantic's own
  messages are not shown: they quote the input, which is package text. Nothing shows a
  traceback. A failure while rendering is a plain 500 page; the server log gets only the
  exception's type.
- **Reports from before Stage 4 recorded network failures** (`correlate.json` without
  `repo_network`) render without the warning.
- **Long evidence** is cut for display: 50 evidence items per rule, 20,000 characters per
  snippet, with a note that the rest is in `report.json`.

Rendering is a pure function of the files: no clock (the dashboard's "how old" is relative to
the newest run, the rule-freeze status to the live report's own `as_of`) and fixed order (the reports' and the
queue's ranks, runs by id), so the same files give the same bytes
(`test_rendering_is_byte_stable`, and `test_rendering_is_byte_stable_and_writes_nothing` for
the dashboard and results). Parsed files are cached by inode, size and modification time
and reloaded when `collect` replaces them; at most 16 live reports and 16 samples are kept
parsed. The live datasets (`eval/live/datasets/*.jsonl.zst`, hundreds of thousands of rows)
are never read: the reports hold every number the pages show. The report cache is bounded by the total size of the
cached `report.json` files (128 MB; the parsed models take several times that), dropping the
least recently used; the newest is kept even if it alone is larger.

- **Very large or deeply nested files** are refused, not parsed: a file over 256 MB is
  checked with `fstat` before it is read and shown as "too large to show (N MB)"; JSON nested
  deeply enough to exhaust the parser's recursion (or memory) is "could not be parsed
  (RecursionError)". Both are ordinary `LoadError`s, cached like the rest, so the run list
  stays a 200 page with one error row (`test_deeply_nested_json_is_an_unreadable_row`,
  `test_files_over_the_cap_are_not_read`).

## Results

`/results` mirrors the Markdown report `kitsunox live eval` writes beside it
(`live-<id>.md`): the same row titles (`live.matrix_title`) and the same number format
(`intervals.percent`: value and Wilson 95% interval), so a figure on a slide can be checked
against either. Definitions are in [evaluation.md](evaluation.md#live-evaluation-phase-9) and
[decision 0019](decisions/0019-live-evaluation.md).

- **Facts:** dataset and its SHA-256 prefix, labels as of (and whether that is before, during
  or after the rule freeze, window B, 2026-11-12 to 2026-11-19), label set, headline D,
  versions (window `all`, and `catch-up` counted apart), flag-worthy versions and misses,
  operational loss (runs that never finished, with their changes) and pending runs. A
  collapsed "How to read the matrices" explains the cells.
- **Per window**, `all` first, then the report's own (A, B, catch-up); a window with no
  versions says so. The headline matrix as a 2x2 grid (reported / not reported against
  flag-worthy / benign; FP with how many are unreviewed), then every matrix:

  | Row | What it is |
  |---|---|
  | Flag-worthy, behaviour truth (**headline**) | A verdict wins (malicious and unwanted positive, benign negative, unverified left out), then an OSV record. |
  | Best / worst case | The headline with the unverified versions put back as the pipeline decided / the opposite: the true value lies between. |
  | Strict (and its best / worst) | Malware only: unwanted is a negative. |
  | OSV truth (**conservative**) | An OSV record wins over any verdict, so no reviewer can clear a labeled version. |
  | OSV only | Verdicts ignored. |
  | + takedowns | npm takedowns without an OSV record count as positives (sensitivity). |
  | Current report after re-scores | Flagged = the report after re-scores (recall only). |
  | D = 3, D = 14 | The headline with another benign delay. |

  Each with TP, FP (unreviewed), FN, TN, recall, precision and FP rate (each with its Wilson
  interval and k/n) and the excluded versions by reason. Then the headline by shape (A update,
  B new package), recall by version, OSV record and publisher account, late labels, verdicts
  per category and unverified reasons, the funnel for malicious and benign versions, why the
  misses were missed, every rule that fired on a reported version with its TP, FP and
  precision (most FP first), and the rule sets.
- **Label timing** and the **review sample's upper bounds**, as in the Markdown.
- **Misses:** every flag-worthy version that wasn't reported (name, version, run, cause,
  shape, OSV ids, verdict at the labels' time, tarball, score). Package text is escaped like
  every other page. A miss has no entry page of its own (it wasn't reported); it links to the
  entry its current verdict was recorded on, if any, and to its run while the run's report is
  on disk.
- **Trend:** every build in `log.jsonl`, newest first (built, dataset, versions, flag-worthy
  recall with k/n and precision, strict reported/total, unverified, newly labeled and how many
  of those were reported, sample versions unreviewed), and from two builds on an inline SVG
  line chart of recall (solid, circles) and precision (dashed, squares). The chart has no
  script and no `style=`: the stylesheet colours it by class, each point carries a native
  `<title>` tooltip, and the table holds the numbers. Lines of the log that don't parse are
  counted in a warning.
- **All reports** on disk, each linked.

`/results/sample` shows one day's sample: progress (how many sampled versions have a verdict,
how many of those saw the behaviour, how many are unverified, how many are not reviewed), the
strata (population, sampled, reviewed, flag-worthy, unverified, not reviewed), each sampled
version with its stratum, run, score, traits (new, hook, watched), rules, tarball and its
verdict now from the verdict log (or "not reviewed"), and every sampled day with its progress.
The page is read-only: sampled versions are in no report, so verdicts on them are recorded
with `kitsunox live verdict` (rank 0), as the page says. Its verdicts are the log's current
ones; a live report counts only those recorded by its labels' `as_of`, so the two can differ.

## Security properties

Everything that came from a package is attacker-controlled: names, versions, publishers,
Stage 4 reasons that quote manifests, titles and explanations, file paths, snippets,
before/after values, URLs, even keys in `by_severity`. The viewer treats it all as data.

| Property | How | Test |
|---|---|---|
| No markup from packages | Every string goes through `html.escape(quote=True)`. Snippets and before/after are in `<pre>`, escaped, newlines kept. | `test_untrusted_fields_cannot_break_any_page` parses every page and allows only the viewer's own tags and attributes: no `<script>`, `<style>`, `<img>`, event handlers or `style=` |
| No hidden or reordering characters | `util.text.strip_hidden`, shared with the Markdown reports, removes by Unicode general category rather than a list: `Cc` (controls, except tab and newline), `Cf` (bidi marks, overrides and isolates, zero-width characters, word joiners, invisible operators, BOM, interlinear annotation, tag characters, musical formatting), `Co` (private use), `Cs` (lone surrogates, which couldn't even be encoded), `Zl`/`Zp`, plus the rest of Unicode's default-ignorable set that isn't `Cf`: variation selectors `FE00`-`FE0F` and `E0100`-`E01EF`, Mongolian free variation selectors, Hangul fillers, Khmer inherent vowels, the combining grapheme joiner and the unassigned ignorable ranges. Real npm malware hid code in exactly these: GlassWorm in variation selectors, os-info-checker-es6 in private-use characters; Trojan Source used bidi overrides. A visible "[N hidden characters removed]" marker says how many were removed: for a reviewer that is a signal in itself. | `test_hidden_characters_are_removed_and_flagged`, `test_payload_hiding_characters_are_counted`, `tests/util/test_text.py` |
| Only safe links | `util.text.safe_url`, also used by the Markdown reports: an external link is emitted only for an ASCII `https://` URL with a plain host name (no user info, so `https://www.npmjs.com@evil.example/` is not a link), an optional port, and no spaces, controls, quotes, angle brackets, backticks or backslashes; with `rel="noopener noreferrer nofollow"`. `javascript:`, `data:`, `http:`, protocol-relative URLs and non-ASCII (homoglyph) host names are shown as text, marked "(not linked)". | `test_unsafe_urls_are_never_links`, `test_plain_https_urls_are_links` |
| No script at all, no inline style | The pages contain no JavaScript. Every response carries `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, so even an escaping bug could not run script or load images, and a form could only post to the viewer itself. | `test_live_pages_carry_the_security_headers` |
| Other headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (and a `<meta name="referrer">`, so following a link to npm or GitHub doesn't leak the local URL), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store`. The `Server` header doesn't name the Python version. | same |
| No path traversal | Request paths are never percent-decoded or joined onto the data directory. The path is split on `/` and matched against fixed names and regexes (`RUN_ID` is `YYYYMMDDTHHMMSSZ-<ecosystem>`; `LIVE_ID` is `live-YYYYMMDDTHHMMSSZ`; a sample day is `YYYY-MM-DD`; ranks and page numbers are positive integers). A run id is then looked up among the directories actually listed in `runs/` (a live report or sample day among the files listed in `eval/live/reports/` and `eval/live/sample/`), and only that listed name is used to build a path. `..`, `%2e%2e`, `%2f`, `%5c`, NUL, `//`, absolute-form targets and paths to real files (`manifest.json`, `report.json`) all get 404 or 400. | `test_traversal_and_unknown_ids_are_404`, `test_non_path_targets_are_400`, `test_unknown_or_malformed_ids_are_404` |
| DNS-rebinding defence | A hostile page that rebinds its own name to 127.0.0.1 still sends that name in `Host`. Requests must carry exactly one `Host` header naming `localhost`, `127.0.0.1`, `[::1]` or the bound address (any port); anything else gets 400. | `test_host_header_check`, `test_live_foreign_host_headers_are_refused`, `test_live_missing_or_repeated_host_is_refused` |
| Loopback by default | See [Listening on another address](#listening-on-another-address). | `test_other_hosts_are_refused_by_default`, `test_every_interface_is_refused_even_when_allowed`, `test_names_that_bind_every_interface_are_refused`, `test_a_loopback_name_bound_elsewhere_is_refused` |
| One write, from its own pages only | GET and HEAD, plus `POST /verdict` (others get 405). The POST needs the token the server made at start with `secrets` (in every form it serves; a page on another site can't read it), an `Origin` naming the viewer when the browser sends one and `Sec-Fetch-Site: same-origin` when sent (403 otherwise), an urlencoded body of at most 16 KiB (413) and each field once. The package and version are taken from the run's report on disk by run id and rank, never from the form; the redirect target must be one of the viewer's own pages. The record is one `O_APPEND` write under `flock`; nothing else is written, and the viewer takes no `DataDir` lock, so it is safe beside a running `collect`. A server on a non-loopback address (`--allow-remote`: no login) or started `--read-only` has no token: no forms, every POST refused. | `test_bad_posts_record_nothing`, `test_live_a_form_post_from_the_page_is_recorded`, `test_a_read_only_viewer_has_no_forms_and_refuses_posts`, `test_rendering_never_writes_to_the_data_dir`, `test_live_writes_are_refused` |
| No network | The viewer fetches nothing. The stylesheet has no `url()` or `@import`. | `test_stylesheet_is_served_and_fetches_nothing` |
| Errors from `http.server` itself | Malformed requests, unknown methods and unsupported HTTP versions get the viewer's own error page and the same headers, not the library's template. HTTP/0.9 (`GET /` with no version) has no headers, so the Host check couldn't apply: it gets a 400, answered as HTTP/1.0 so the status line and headers go out. | `test_live_malformed_requests_get_our_error_page`, `test_live_http09_and_bare_request_lines_are_refused` |
| No tracebacks in the log | A client that hangs up mid-response (`BrokenPipeError`, `ConnectionResetError`) or times out is ignored; any other error is logged as one line with the exception's type. The standard library would print a traceback, which shows absolute paths. | `test_live_client_hangups_and_errors_print_no_traceback`, `test_live_render_errors_show_no_traceback` |
| Slow or many clients | Each connection has its own daemon thread, a 30-second idle timeout on every read, and a 30-second total deadline after which its socket is shut down, so a client trickling one byte at a time can't hold a thread. At most 32 connections are served at once; beyond that a connection gets a short 503 page (same headers) and is closed. A browser opens at most about six. | `test_live_slow_clients_are_cut_at_the_deadline`, `test_live_connections_beyond_the_cap_get_503` |

## Known limits

- **One reader, no accounts.** It is built for the person running the collection. There is
  no login and no TLS, so verdicts can be recorded only on a loopback address (an SSH tunnel
  works); every viewer-recorded verdict is `owner`.
- **Package-level pages don't exist yet.** The queue links each version; a page with one
  package's history across runs (including versions that weren't reported) would need data
  the queue doesn't keep.
- **Escaping covers HTML, not meaning.** A package name that imitates another one
  (homoglyphs in the name itself) is shown as it is; the viewer only drops invisible and
  reordering characters. Typosquatting is a Stage 1 concern.
- **Some legitimate text is flagged too.** Emoji use the zero-width joiner and variation
  selector 16 (red heart is U+2764 U+FE0F), and some scripts use joiners; those are removed and counted like any
  other hidden character. Package text (names, versions, evidence) rarely has them, and a
  false "[1 hidden character removed]" costs a glance, while a missed one could hide a
  payload.
  The carriage return of a CRLF line ending and a byte order mark at the very start of a
  value are the exceptions: they are removed without being counted, because ordinary Windows
  and BOM-prefixed files carry them (a lone carriage return or a BOM elsewhere still counts).
- **The 30-second deadline is per connection,** so a page that takes longer than that to
  render (a report near the 256 MB cap) is cut off. Reports are far smaller in practice.
- **Report text is truncated for display only.** `report.json` keeps everything.
- **Results are as built, not live.** `/results` shows what the last `kitsunox live eval` (or
  `collect`'s daily build) wrote; a verdict recorded since moves no number until the next
  build. The sample page and the dashboard's tally do read the verdict log as it is now.
