# Local web viewer

> **Status:** implemented 2026-10-29 (`src/kitsunox/web/`, roadmap Phase 11). It reads the
> same `report.json` and `queue.json` that the Markdown views come from. It adds no new data
> and no new dependencies: the server is the standard library's `http.server`.

## Purpose

The Markdown queue and pages (see [stages/report.md](stages/report.md)) work in an editor, but
moving between the queue, a run and one version's evidence means opening files by hand. The
viewer serves the same data as linked pages in a browser on the collection machine. It does
nothing else: it never writes, never fetches, and never runs package code.

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
| `/` | The review queue (`data/queue/queue.json`): packages ranked by score, then severity, then name. Each row has the score, severity, every reported version (newest first, each linking to its entry in the run that reported it most strongly), the rules with the number of versions they fired on, watched, and last publish time. Unreadable reports the queue left out are listed with links to their runs. |
| `/runs` | Runs with a `report/report.json`, newest first, 50 per page (`/runs/page/N`): release window, versions analysed, how many to review, counts by severity, and a note when Stage 4 couldn't compare versions with their repository because of the network. |
| `/runs/<run_id>` | One run's report: summary, the network warning, the versions to review (rank, package, score, severity, top three rules, watched), and Stage 4's settings (`correlate.json`) in a collapsed block. |
| `/runs/<run_id>/entries/<rank>` | One version: score and Stage 4's reason; what changed (previous version, publish time and publisher, popularity); where to look (npm, the file browser, npmdiff, the repository and the repository at the compared commit); how the score adds up (each rule once, with its weight and number of findings, and the total); and every finding grouped by stage and rule, with its explanation and evidence (file and lines, the snippet, before/after side by side). Links go to the previous and next entries. |
| `/static/style.css` | The one stylesheet. |

Anything else is a 404.

- **No queue yet** or **no run with a report** is a short message, not an error.
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

Rendering is a pure function of the files: no clock and fixed order (the reports' and the
queue's ranks, runs by id), so the same files give the same bytes
(`test_rendering_is_byte_stable`). Parsed files are cached by inode, size and modification time
and reloaded when `collect` replaces them. The report cache is bounded by the total size of the
cached `report.json` files (128 MB; the parsed models take several times that), dropping the
least recently used; the newest is kept even if it alone is larger.

- **Very large or deeply nested files** are refused, not parsed: a file over 256 MB is
  checked with `fstat` before it is read and shown as "too large to show (N MB)"; JSON nested
  deeply enough to exhaust the parser's recursion (or memory) is "could not be parsed
  (RecursionError)". Both are ordinary `LoadError`s, cached like the rest, so the run list
  stays a 200 page with one error row (`test_deeply_nested_json_is_an_unreadable_row`,
  `test_files_over_the_cap_are_not_read`).

## Security properties

Everything that came from a package is attacker-controlled: names, versions, publishers,
Stage 4 reasons that quote manifests, titles and explanations, file paths, snippets,
before/after values, URLs, even keys in `by_severity`. The viewer treats it all as data.

| Property | How | Test |
|---|---|---|
| No markup from packages | Every string goes through `html.escape(quote=True)`. Snippets and before/after are in `<pre>`, escaped, newlines kept. | `test_untrusted_fields_cannot_break_any_page` parses every page and allows only the viewer's own tags and attributes: no `<script>`, `<style>`, `<img>`, event handlers or `style=` |
| No hidden or reordering characters | `util.text.strip_hidden`, shared with the Markdown reports, removes by Unicode general category rather than a list: `Cc` (controls, except tab and newline), `Cf` (bidi marks, overrides and isolates, zero-width characters, word joiners, invisible operators, BOM, interlinear annotation, tag characters, musical formatting), `Co` (private use), `Cs` (lone surrogates, which couldn't even be encoded), `Zl`/`Zp`, plus the rest of Unicode's default-ignorable set that isn't `Cf`: variation selectors `FE00`-`FE0F` and `E0100`-`E01EF`, Mongolian free variation selectors, Hangul fillers, Khmer inherent vowels, the combining grapheme joiner and the unassigned ignorable ranges. Real npm malware hid code in exactly these: GlassWorm in variation selectors, os-info-checker-es6 in private-use characters; Trojan Source used bidi overrides. A visible "[N hidden characters removed]" marker says how many were removed: for a reviewer that is a signal in itself. | `test_hidden_characters_are_removed_and_flagged`, `test_payload_hiding_characters_are_counted`, `tests/util/test_text.py` |
| Only safe links | `util.text.safe_url`, also used by the Markdown reports: an external link is emitted only for an ASCII `https://` URL with a plain host name (no user info, so `https://www.npmjs.com@evil.example/` is not a link), an optional port, and no spaces, controls, quotes, angle brackets, backticks or backslashes; with `rel="noopener noreferrer nofollow"`. `javascript:`, `data:`, `http:`, protocol-relative URLs and non-ASCII (homoglyph) host names are shown as text, marked "(not linked)". | `test_unsafe_urls_are_never_links`, `test_plain_https_urls_are_links` |
| No script at all, no inline style | The pages contain no JavaScript. Every response carries `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, so even an escaping bug could not run script, load images or submit a form. | `test_live_pages_carry_the_security_headers` |
| Other headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (and a `<meta name="referrer">`, so following a link to npm or GitHub doesn't leak the local URL), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, `Cache-Control: no-store`. The `Server` header doesn't name the Python version. | same |
| No path traversal | Request paths are never percent-decoded or joined onto the data directory. The path is split on `/` and matched against fixed names and regexes (`RUN_ID` is `YYYYMMDDTHHMMSSZ-<ecosystem>`; ranks and page numbers are positive integers). A run id is then looked up among the directories actually listed in `runs/`, and only that listed name is used to build a path. `..`, `%2e%2e`, `%2f`, `%5c`, NUL, `//`, absolute-form targets and paths to real files (`manifest.json`, `report.json`) all get 404 or 400. | `test_traversal_and_unknown_ids_are_404`, `test_non_path_targets_are_400` |
| DNS-rebinding defence | A hostile page that rebinds its own name to 127.0.0.1 still sends that name in `Host`. Requests must carry exactly one `Host` header naming `localhost`, `127.0.0.1`, `[::1]` or the bound address (any port); anything else gets 400. | `test_host_header_check`, `test_live_foreign_host_headers_are_refused`, `test_live_missing_or_repeated_host_is_refused` |
| Loopback by default | See [Listening on another address](#listening-on-another-address). | `test_other_hosts_are_refused_by_default`, `test_every_interface_is_refused_even_when_allowed`, `test_names_that_bind_every_interface_are_refused`, `test_a_loopback_name_bound_elsewhere_is_refused` |
| Read-only | GET and HEAD only (others get 405 with `Allow: GET, HEAD`). Files are only opened for reading; the viewer takes no lock and writes nothing, so it is safe beside a running `collect`. | `test_rendering_never_writes_to_the_data_dir`, `test_live_writes_are_refused` |
| No network | The viewer fetches nothing. The stylesheet has no `url()` or `@import`. | `test_stylesheet_is_served_and_fetches_nothing` |
| Errors from `http.server` itself | Malformed requests, unknown methods and unsupported HTTP versions get the viewer's own error page and the same headers, not the library's template. HTTP/0.9 (`GET /` with no version) has no headers, so the Host check couldn't apply: it gets a 400, answered as HTTP/1.0 so the status line and headers go out. | `test_live_malformed_requests_get_our_error_page`, `test_live_http09_and_bare_request_lines_are_refused` |
| No tracebacks in the log | A client that hangs up mid-response (`BrokenPipeError`, `ConnectionResetError`) or times out is ignored; any other error is logged as one line with the exception's type. The standard library would print a traceback, which shows absolute paths. | `test_live_client_hangups_and_errors_print_no_traceback`, `test_live_render_errors_show_no_traceback` |
| Slow or many clients | Each connection has its own daemon thread, a 30-second idle timeout on every read, and a 30-second total deadline after which its socket is shut down, so a client trickling one byte at a time can't hold a thread. At most 32 connections are served at once; beyond that a connection gets a short 503 page (same headers) and is closed. A browser opens at most about six. | `test_live_slow_clients_are_cut_at_the_deadline`, `test_live_connections_beyond_the_cap_get_503` |

## Known limits

- **One reader, no accounts.** It is built for the person running the collection. There is
  no login, no TLS, and no reviewer verdicts (cleared/confirmed) yet: see "Not yet" in
  [stages/report.md](stages/report.md).
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
