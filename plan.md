# ferrite — plan

A Burp Suite-style intercepting proxy for web app pentesting, written in Rust with an egui UI.

## Status (built, tested live)

All 11 planned milestones plus extra Burp features are implemented and verified against real
traffic and a local vulnerable server. ~6900 lines across 19 modules, 35 passing tests + 1 ignored
network test. Tabs: **Target** (site map + passive/active scan issues), **Proxy** history,
**Intercept**, **Repeater**, **Intruder**, **Sequencer**, **Decoder**, **Comparer**, **Settings**.

Delivered beyond the original v1 scope:

- **Passive scanner** — HSTS, clickjacking, CSP, nosniff, cookie flags, version disclosure, CORS,
  reflected input, error/stack traces, private IPs, directory listing, cleartext passwords, JWTs.
- **Active scanner** (per-request, from the context menu) — probes query, form, JSON and cookie
  parameters for SQLi (error + time-based blind), reflected XSS, path traversal, SSTI, OS command
  injection (time-based blind) and open redirects. Time-based findings are confirmed with a
  zero-delay control to reject naturally slow responses.
- **Sequencer** — live token capture with per-position entropy, bit-balance and sequence analysis.
- **Message viewers** — Raw / Pretty (JSON) / Hex / Params, syntax highlighting, in-pane search.
- **Request export** — copy as curl, as Python `requests`, or as an auto-submitting CSRF PoC.
- **Response modification** — unhide hidden fields, enable disabled inputs, strip maxlength,
  remove JS/HTML5 validation, drop cookie Secure flag.
- **TLS pass-through** — per-host regex list to tunnel pinned apps untouched (verified: badssl keeps
  its real cert while others get the ferrite CA).
- **Settings persistence** — scope, rules, mods, upstream saved to `~/.config/ferrite/settings.json`.
- **Shortcuts** — Ctrl+R → Repeater, Ctrl+I → Intruder, Ctrl+F forward (Intercept), Ctrl+Enter send.
- **DNS cache** (60s) so Intruder/Sequencer don't pay a lookup per request.

Later additions (session 2):

- **Project save/load** — history, WebSockets and issues to a gzipped `.ferrite` file (Project menu).
- **Autosave on exit** to `~/.config/ferrite/autosave.ferrite`; next launch offers to restore it.
- **Content discovery** tab — wordlist (built-in or file) + extensions against a target, flags what
  exists, hides 404s, sorts by interesting status. Verified: 61 probes → 7 found on a local server.
- **Per-flow notes** — editable in the detail pane, shown as a column, searchable, saved in projects.
- **Theme** — System / Dark / Light, persisted.
- **Help menu** — keyboard-shortcut reference.
- **Copy response body**, and active-scan now also covers JSON and cookie parameters.
- **HAR 1.2 export** (Project menu; `.gz` suffix gzips) for interop with other tools.
- **Copy as fetch** — a browser `fetch()` snippet for the devtools console.
- **WebSocket Repeater** tab — open a `ws://`/`wss://` connection and send/receive messages by
  hand, with a sent/received log. Verified live: `→ hello` echoed back `← hello` over wss + TLS.

Session-2 polish:

- **Status-class quick filters** (All / 2xx / 3xx / 4xx / 5xx) in the Proxy toolbar.
- **Wall-clock timestamps** per flow (Started column, UTC), saved in projects.
- **Record in-scope traffic only** option (still proxies everything, just filters history).
- **Decoder** adds ROT13 and gzip (encode/decode); **Comparer** adds Swap A/B.
- **Match & replace** adds request/response first-line targets (rewrite method, path, status).
- **Intruder** results → Copy as CSV (RFC 4180 quoting).
- **CLI** `--help` / `--version`.

- **Logger** tab — one combined, searchable, per-tool-filterable list of every request sent by
  Repeater, Intruder, Discovery, Sequencer and the active Scanner. Rows carry the request, so the
  full "Send to…/Copy as…" context menu works from here too. Verified live.
- **Discovery recursion** — found directories are queued and scanned deeper up to a max depth.
  Verified live: base scan found /admin + /api, recursed to /admin/backup + /api/admin, stopped at depth 2.
- **Hidden-parameter miner** — the active scanner also tries ~40 common parameter names not present
  in the request and reports any the server reflects (like Burp's Param Miner). Hermetic test covers it.
- Settings QoL: copy CA path / config dir.

- **Crawler / Spider** tab — from a start URL, fetches pages, extracts href/src/action links,
  resolves them, and crawls in-scope same-host pages breadth-first (max pages / depth / threads).
  Each page is fed into the proxy history, so the site map and passive scanner light up
  automatically. "Spider from here" is in the request context menu. Link resolution + extraction
  are unit-tested; the live GUI crawl walk-through is now completed (see session 3 below).

### Session 3 — crawler fixes and end-to-end verification (2026-10-17)

- **URL resolution** now uses the `url` crate (already a transitive dependency). Parent paths,
  dot segments, query-only references, mixed-case schemes/hosts and default ports normalize
  correctly; fragments are removed before deduplication. Only HTTP(S) URLs are accepted.
- **Exact request budget** — concurrent waves cannot exceed Max pages; failed requests also
  consume the budget. Depth, same-host and configured scope boundaries are covered by tests.
- **Compressed pages** — link extraction runs on the decoded response body, so gzip/chunked
  HTML can be crawled using the existing HTTP decoding helpers.
- **Scope and stop controls** — In-scope only also checks the start URL. Stop keeps the run
  active until its current batch finishes, preventing a new run from overlapping it.
- **Regression coverage** — local HTTP fixture exercises gzip links, normalized duplicates,
  parent links, exact page limits, depth, host/scope boundaries and paired history events.
- **Live GUI verified** using isolated temporary settings and a local HTTP fixture: Start crawl
  fetched `/`, `/dir/page`, `/a`, `/b`, `/c`, `/end`; excluded a different hostname and avoided
  recrawling `/dir/./page#top`. All six flows appeared in Proxy history and Target generated
  four passive issues. No external target was contacted.
- **Validation:** `cargo test --locked` → 23 passed, 1 ignored; `cargo check --offline` and
  `cargo build --release --locked --offline` passed without warnings. Socket fixture tests
  require execution outside the restricted filesystem/network sandbox.
- `cargo fmt --check` currently reports existing formatting differences across the repository;
  a repository-wide formatting pass remains separate work.

~6900 lines, 19 modules, 23 passing tests + 1 ignored network test. Release build is warning-clean.
Everything above is verified live or by tests, including the Crawler's GUI run.

### Session 4 — Burp-style investigation workflows (in progress, 2026-10-17)

- **Crawler redirects:** Follow redirects toggle; redirects preserve link depth, pass through the
  same host/scope/request-budget checks, and loops terminate via URL deduplication. Connection
  failures are visible. All attempts, including failures, appear in Logger. Local fixture coverage
  checks redirects at depth zero, disabled following, loops, off-host and excluded destinations.
- **Logger message inspection:** selectable rows with request/response viewers and connection
  errors; context menus work across the entire row and include response actions. Retention is
  bounded at 10,000 entries / 64 MiB of request and response bytes, with discarded-entry counts.
- **Search tab:** background snapshot search across Proxy history and/or Logger; literal or regex,
  case sensitivity, scope filtering, request/response selection, headers/decoded bodies/URLs/notes.
  Results include match counts and excerpts, original messages and Send-to actions. Stop returns
  partial results. Results retain their snapshot even if history changes later.
- **Repeater Inspector:** edit/add/remove decoded query, form and cookie parameters, plus a JSON
  body editor/formatter. Apply explicitly encodes modified groups and updates body framing;
  unchanged groups preserve their existing encoding. JSON errors and invalid cookies are reported.
- **Repeater workflow:** duplicate tabs; closing an earlier tab preserves the current tab; exchange
  history restores target, request, response and timing, with navigation disabled during sends.
- **Redirect fidelity:** Repeater resolves parent/query/absolute redirects, preserves HEAD and
  appropriate methods, strips credentials across origins, rejects non-HTTP(S)/credential-bearing
  destinations, and drops fragments. IPv6 Host headers now include brackets, and URL path handling
  preserves queries on URLs without a slash.
- **GUI verified:** Search located a literal inside a gzip response and opened its exchange;
  Inspector added `name=hello world`, produced `name=hello+world` in the raw request, and sent
  it to the local server; Logger displayed both that request and its response. Narrow Inspector
  fields were corrected after the check; response viewers default to Pretty for decoded bodies.

### Session 5 — projects, interoperability and session workflows (2026-10-17)

- **Repeater persistence:** projects/autosave include named tabs, targets, edits, responses,
  history and cookie-reuse choices. Legacy project files load with empty Repeater/Organizer state.
  Restored tabs get fresh runtime IDs so old in-flight responses cannot overwrite them.
- **HAR import:** Project menu appends plain/gzipped HAR as reconstructed HTTP messages, with
  form data, cookies, base64 bodies, timings and timezone-aware timestamps. Entries are validated
  before history changes; multipart/file bodies without raw content report an error.
- **HAR export fidelity:** timestamps reflect capture time; binary response bodies use standard
  base64 content encoding; binary request bodies use the `_encoding` extension. Imported decoded
  bodies have compression/chunk headers removed and their lengths corrected.
- **Sessions tab:** in-memory cookie jar captures Set-Cookie from proxy and tool responses;
  supports manual add/update, value editing, filtering and deletion. Cookies are deliberately
  host-bound (Domain does not broaden delivery), with Path, Secure, HttpOnly and expiry shown.
  Repeater, Crawler and Discovery each expose an opt-in Use session cookies toggle. Other tool
  requests retain their explicit Cookie headers. Retention is capped at 2,000 cookies.
- **Organizer:** independent request/response snapshots, editable names/tags/notes and progress
  states, searchable and scope-filterable, with message viewers and Send-to actions. Add to
  Organizer is available in the common request action menu; projects/autosave include its state.
- **Validation:** 35 tests passed + 1 ignored before Organizer; full post-Organizer checks and
  live Sessions/project/Organizer verification are next. Session tests include a real local server
  rotating an authentication cookie and asserting the next request's Cookie header.

Next: live checks for the new Sessions/project/Organizer flows, request method/body conversions,
robust HTML parsing and authenticated crawler headers. Cookie jar is intentionally in-memory;
full browser cookie policy and cross-subdomain delivery are not implemented.

Open questions from the original plan, as resolved: listen address is a CLI arg; intercept catches
responses and WebSockets too (toggle); Intruder has prefix/suffix/null-payload processors; settings
persist to disk.

## Decisions

- **Use case:** web app pentests. The browser points at the proxy.
- **Storage:** live history is in memory; project files and autosave persist it between sessions.
- **Protocols:** HTTP/1.1 + TLS, HTTP/2, WebSockets.
- **CA:** generated on first run and saved to `~/.config/ferrite/ca.{pem,key}`. The user imports it into the browser.
- **v1 tools:** Proxy history, Intercept, Repeater, Intruder (all 4 attack types), Decoder, Comparer.
- **v1 extras:** Target scope, history search/filter, Match & replace, upstream proxy (HTTP + SOCKS5).
- **Still out of scope:** extensions API, Collaborator/OOB, an embedded browser.
  Project save files, scanning and crawling/spidering are now implemented.

## Crates

| Need | Crate |
|---|---|
| UI | `eframe`/`egui`, `egui_extras` (tables) |
| MITM proxy | `hudsucker` (hyper + rustls + rcgen, h1/h2/WebSockets) |
| Async runtime | `tokio` |
| Raw sends (Repeater/Intruder) | `tokio-rustls`, `hyper` client for h2 |
| Body decoding | `flate2`, `brotli`, `zstd` |
| Rules and filters | `regex` |
| Decoder | `base64`, `percent-encoding`, `hex` |
| Comparer | `similar` |
| Upstream proxy | `tokio-socks`, plus a hand-written HTTP CONNECT connector |

## Architecture

```
┌────────────── tokio runtime (bg thread) ──────────────┐
│ hudsucker proxy ── HttpHandler / WebSocketHandler     │
│   ├─ scope check, match & replace                     │
│   ├─ intercept: send to UI, await oneshot reply       │
│   └─ emit Flow events ──────────────┐                 │
│ Repeater / Intruder senders ◄───────┼── UI commands   │
└─────────────────────────────────────┼─────────────────┘
                                      ▼ mpsc + ctx.request_repaint()
┌──────────────────── eframe UI thread ─────────────────┐
│ App { flows: Vec<Flow>, tabs, intercept_queue, ... }  │
│ Tabs: Proxy | Intercept | Repeater | Intruder |       │
│       Decoder | Comparer | Settings                   │
└───────────────────────────────────────────────────────┘
```

- `Flow` = id, timestamp, request (raw bytes + parsed head), response (optional), timing, WebSocket messages (optional).
- UI never blocks. The proxy task owns the network side and the UI owns all state.
- Communication uses two channels: `proxy_tx` carries events to the UI and `cmd_tx` carries commands to the runtime.

## Milestones

1. **Skeleton:** eframe window, tokio runtime on a background thread, channels wired up.
2. **Proxy + CA:** hudsucker listening on `127.0.0.1:8080`. CA generated and persisted. Flows appear in the history table.
3. **History view:** sortable table (`#`, host, method, path, status, length, time). Request/response split pane in raw, headers or pretty view. Bodies decompressed for display.
4. **Search/filter + scope:** filter bar for host, method, status and body regex. Scope include/exclude regex list, plus a "show in-scope only" toggle.
5. **Intercept:** on/off toggle and a queue of pending requests (later responses). The user edits raw text, then forwards or drops. Scope-aware.
6. **Repeater:** "Send to Repeater" from history. Tabbed editors. Raw HTTP/1.1 goes over TCP/TLS as typed bytes; h2 goes through the hyper client. Shows the response and its timing.
7. **Match & replace:** ordered rules, each with target (request header, request body, response header, response body), regex and replacement. Applied in the handler.
8. **WebSockets:** message log per connection in history. Intercept and edit messages.
9. **Intruder:** `§marker§` positions in a raw request. Payload sets from a list or file. Sniper, battering ram, pitchfork and cluster bomb. Concurrency limited by a semaphore with a configurable number of threads. Results table (payload, status, length, time) with a pause/stop control.
10. **Decoder / Comparer:** encode and decode as base64, URL or hex, with chaining. Comparer shows a side-by-side or unified diff of two items sent from history or Repeater.
11. **Upstream proxy:** HTTP CONNECT and SOCKS5 chaining in settings. Used by the proxy, Repeater and Intruder.

Each milestone ends in a runnable build that is tested against a real target, for example a local DVWA or Juice Shop instance.

## Risks

- **Raw fidelity:** hyper normalizes header case and ordering. Repeater and Intruder use their own HTTP/1.1 writer so requests go out exactly as typed. h2 cannot be raw by nature.
- **Upstream proxy in hudsucker:** its client connector is swappable, but CONNECT chaining needs a custom connector. Spike this before milestone 11.
- **Memory growth:** in-memory history with large bodies grows without limit. Cap stored body size (e.g. 10 MB per body) and show a truncation marker.
- **Intercept deadlocks:** a held request blocks the browser connection. Add an auto-forward timeout and a "forward all" button when intercept is turned off.
- **HTTP/2 display:** show h2 as an HTTP/1.1-style pseudo-raw view and mark it as h2.

## Open questions

- Should the listen address and port be configurable in the UI, or only by CLI flag?
- Should Intercept also catch responses in v1, or requests only?
- Are Intruder payload processors (prefix, suffix, encode, hash) needed in v1, or are raw lists enough?
- Should there be a way to save and load settings (scope, rules) even though traffic is not persisted?
