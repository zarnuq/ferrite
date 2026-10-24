# Burp behavior notes — precise mechanics to replicate

Third companion to `burp-architecture.md` (how subsystems connect) and
`burp-feature-spec.md` (every feature + tunable). This doc records the *non-obvious
runtime behaviors* — the things the API signatures and config keys don't tell you, that
ferrite has to get right to behave like Burp. Synthesized from Burp's own documentation
in ferrite's own words; no PortSwigger prose is copied.

## Crawler

- **Locations are identified by content, not URL.** Burp Scanner builds a directed graph
  of application locations and keys each node on what the page *contains*, not the URL
  used to reach it. This is why it handles CSRF tokens, cache-busters, and session IDs in
  URLs, and apps that serve different content from the same URL depending on state.
- **It never jumps to a pending link.** The crawler tracks unvisited edges, but to visit
  one it either navigates directly from the current location or reverts to the start and
  navigates from there — mimicking a real user. No out-of-context GETs.
- **Breadth-first**, prioritizing new content; builds link fingerprints to skip
  already-visited locations; configurable cutoffs bound "infinite" apps (calendars, etc.).
- **State-change tracking.** When path B→C transitions the app from state 1 to state 2 and
  link D then leads somewhere different, Burp doesn't write D off as non-deterministic — it
  records the state-changing path D depends on, so it can reliably reach that location again.
- **Dynamic session handling for free.** Crawl requests are constructed from the previous
  response, so CSRF tokens in URLs/form fields are followed automatically — no macros or
  session rules needed during a crawl.
- **ferrite:** `src/crawler.rs`. Current crawler is link-following; the content-based node
  identity + directed-graph state tracking is the hard part to match. Gap.

## Scanner audit

- **Three phases, run in parallel:** passive (observe existing traffic), active (send
  modified requests), JavaScript analysis (DOM-based issues).
- **Passive consolidation.** Identical passive issues from shared templates/platform
  config are collapsed to a single instance reported at the most relevant level (web root
  or shared folder); every occurrence is still kept as evidence.
- **Active intensity tiers:** light → medium → intrusive. The scan-type gates
  (`scan_type_light_active` etc. in the config) select which tiers run.
- **JavaScript analysis is hybrid:**
  - *Static:* parses JS to an AST and does taint tracking — tainted **sources** (attacker
    inputs) → dangerous **sinks** → **taint paths** between them. Finds paths dynamic
    analysis can't reach, but alone yields lower-confidence findings.
  - *Dynamic:* loads the response in an embedded headless browser, injects payloads into
    attacker-controllable DOM locations, executes the JS, and simulates interactions
    (e.g. firing `onclick`) to confirm injected data reaches a sink. Confirmation upgrades
    confidence.
- **ferrite:** `src/scanner.rs`, `src/deep_scan.rs`. Has passive + active differential
  probes; passive consolidation, intensity tiers, and JS AST taint analysis are gaps.

## Intruder (config model)

Attack = base request + payload **positions** + **attack type** (how payloads map to
positions) + **payload type** (wordlist or generator) + **payload processing** rules +
**resource pool**. Attack config is saveable/loadable and copyable between tabs, with or
without the positions. ferrite `src/intruder.rs` matches this model (now with built-in
presets); grep-match/extract columns and per-attack resource-pool binding are the polish
items to confirm.

## Collaborator (OOB)

- **Payloads are subdomains** of the Collaborator server domain. A payload can embed the
  full server address or just the Collaborator ID (ID-only is stealthier).
- **Interaction sequence:** target does a **DNS lookup** on the payload subdomain, then may
  open a further connection (**HTTP**, **SMTP**). The server records all three types.
- **Polling every 60 s** by default (manual "Poll now" available); unread count shown on
  the tab. Results filterable by protocol (HTTP/DNS/SMTP).
- **Per-tab tables share one polling schedule** — generating payloads in different tabs
  partitions results without increasing server load.
- Public server domains rotate (currently `*.oastify.com`, `*.burpcollaborator.net`) to
  dodge WAF blocklists; private/self-hosted server supported.
- **ferrite:** `src/interactsh.rs`, `src/callbacks.rs`. Interactsh already covers OOB;
  match the 60 s poll cadence, ID-only payload option, and per-tab result partitioning.

## DOM Invader (client-side)

Browser-extension tool (lives in Burp's built-in browser DevTools). Capabilities:
- **DOM XSS**: augments the DOM view to show controllable sinks on the page, the XSS
  context, and how input is sanitized — via a canary string propagated source→sink.
- **Web messages**: logs/modifies/replays `postMessage()` traffic, and can auto-probe by
  sending crafted messages.
- **Client-side prototype pollution**: auto-finds pollution sources and scans for
  controllable gadgets reaching dangerous sinks.
- **DOM clobbering** detection.
- **ferrite:** `assets/dom-probe.js` + `src/browser_lab.rs` already instrument the DOM.
  The fuller targets are canary source→sink mapping, postMessage interception, and
  prototype-pollution gadget scanning.

## Session handling rules

- **Each rule = scope + ordered actions.** Scope = which tools, URLs, and parameters the
  rule applies to. On **every outgoing request**, Burp picks the matching rules and runs
  all their actions in order.
- **Action types** include: add cookies from the cookie jar; check the session is valid
  and, if not, run a macro to log back in and update the jar; run a macro to fetch a fresh
  token (e.g. `__csrftoken`) and substitute it; set a specific cookie/param; invoke an
  extension action.
- **Rules form a hierarchy** — broad rules plus narrower per-domain/per-URL rules.
- **Scanner exemption:** crawl and crawl-driven audit ignore session rules *except* "set a
  specific cookie/param" and "invoke extension action" (the crawler handles sessions
  dynamically on its own).
- **Session handling tracer**: per-request log of which rules/actions ran and how each
  mutated the request — essential for debugging rule chains (has runtime overhead).
- **ferrite:** `src/session.rs`, `src/macros.rs`. The scoped rule engine that runs ordered
  actions pre-send (hung off a shared send hook) + a tracer view are the pieces to build.

## Match and replace

Rules run **in listed order**, each making its replacement, for every message through the
proxy; order is user-reorderable (matters when one rule's output feeds another). Settings
mode (checkbox/dropdown rules) + script mode (Java scripts, HTTP only). WebSocket rules are
a separate table. **ferrite:** `src/rules.rs` applies rules in order already; the built-in
response-modification toggles now match Burp's set (unhide/enable/remove-maxlength/
remove-js-validation/strip-secure/highlight-unhidden/remove-all-js/remove-object/convert-https).

## Engagement tools

Context-menu utilities worth cloning into ferrite's right-click menus:
- **Find references** — search all tools for responses linking to the current item.
- **Discover content** — brute/guess unlinked content (ferrite has `src/discovery.rs`).
- **Schedule task** — run tasks at set times/intervals.
- **Target analyzer** — estimate attack surface / effort.
- **Generate CSRF PoC** — emit HTML that reissues the current request (clone candidate).
- **Manual simulator** — generate traffic resembling manual testing.

## Where these came from

Burp's bundled official docs (410 HTML pages, extracted to Markdown locally — not in this
repo for copyright) under `resources/Documentation/burp/documentation/`, plus the Montoya
API and config defaults. For exact algorithm internals (crawl graph diffing, h2 race
timing, CA minting) a live Frida trace is still required — see the end of
`burp-architecture.md`.
