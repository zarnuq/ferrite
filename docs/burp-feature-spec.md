# Burp feature spec — complete catalog for cloning

Companion to `burp-architecture.md`. That doc explains *how* subsystems work; this one
is the exhaustive *what* — every feature and tunable Burp 2026.9.1 exposes, taken from
`resources/Preferences/{ProjectDefaults,UserDefaults}.json` and
`resources/BuiltInConfigs/`. Use it as the clone checklist.

Status marks are best-effort against the current ferrite tree and should be re-checked
before work: **[have]** seen in code, **[part]** partial, **[gap]** not found, **[?]** verify.

---

## A. Proxy

Interception (`proxy.intercept_client_requests` / `intercept_server_responses`):
`do_intercept`, rule list, `automatically_update_content_length_header_when_edited`,
`automatically_fix_missing_or_superfluous_new_lines_at_end_of_request`. WebSocket
intercept: client→server, server→client, in-scope-only. **[part]** `src/intercept.rs`.

Match/replace: `proxy.match_replace_rules` (12 built-in defaults), WS variant,
out-of-scope disable. **[have]** `src/rules.rs`.

**Response modification (HTML rewriting) — likely [gap], high clone value**
(`proxy.response_modification`): `unhide_hidden_form_fields`, `enable_disabled_form_fields`,
`remove_input_field_length_limits`, `highlight_unhidden_fields`,
`remove_javascript_form_validation`, `remove_all_javascript`, `remove_object_tags`,
`remove_secure_flag_from_cookies`, `convert_https_links_to_http`. Each is a response-body
rewrite toggle.

Proxy misc (`proxy.miscellaneous`): `unpack_gzip_deflate_in_requests/responses`,
`set_connection_header_on_requests`, `set_connection_close_header_on_responses`,
`use_http_10_in_requests_to_server`, `use_http_10_in_responses_to_client`,
`use_http1_keep_alive`, `strip_proxy_headers_in_incoming_requests`,
`strip_sec_websocket_extensions_headers`, `remove_unsupported_encodings_from_accept_encoding`,
`disable_web_interface`, `suppress_burp_error_messages_in_browser`,
`disable_logging_to_history_and_site_map` (+ out-of-scope variant).

SSL pass-through (`proxy.ssl_pass_through`): rules, `apply_to_out_of_scope_items`,
`automatically_add_entries_on_client_ssl_negotiation_failure`.

Request listeners: `proxy.request_listeners` (bind port/iface, invisible proxying,
redirect, cert per host).

---

## B. Repeater  **[part]** `src/repeater.rs`

`allow_http2_alpn_override` [gap], `enable_http1_keep_alive`,
`enable_http2_connection_reuse`, `enforce_protocol_in_redirections` [gap],
`process_cookies_in_redirections`, `strip_connection_header_over_http2` [gap],
`normalize_line_endings` [gap], `unpack_gzip_deflate`, `update_content_length` [have],
`follow_redirections` (never/…), `streaming_response_timeout_millis` (600000).

---

## C. Intruder  **[have]** `src/intruder.rs`

Four attack types + Null, `§` markers, payload processing, URL-encode, number ranges,
built-in presets (`assets/payloads/*.pay`), resource pool selection. At parity. UI
options (`user_options.intruder`): sidebar position/mode, tab-bar layout.

---

## D. Scanner — full engine config schema

The complete crawl + audit option vocabulary (union of all `BuiltInConfigs`). ferrite's
`src/scanner.rs` + `src/crawler.rs` + `src/deep_scan.rs` + `src/discovery.rs` cover a
subset; the items below are the full target.

**Crawl** (`crawler.*`):
- `crawl_limits`: `maximum_crawl_time`, `maximum_request_count`, `maximum_unique_locations`.
- `crawl_optimization`: `crawl_strategy` (fastest…most complete), `dom_idle_threshold`,
  `network_idle_threshold`, `await_navigation_timeout`, `crawl_using_provided_logins_only`.
- `live_passive_crawl`: `add_links`, `add_form_submissions`, `add_all_urls`,
  `add_same_domain`, `add_urls_in_scope`, `add_item_itself`, `scope_type` + custom scope.
- `error_handling`: `number_of_follow_up_passes`, timed-out count/percentage to pause.

**Audit** (`scanner.*`):
- `audit_optimization`: `scan_accuracy`, `scan_speed`, `skip_ineffective_checks`,
  `maintain_session`, `follow_redirections`, `consolidate_passive_issues`,
  `maximum_crawl_and_audit_time`.
- `insertion_point_types`: url params, url path filename, url path folders, body params,
  cookies, param name, http headers, entire body. **This is where to inject.**
- `frequently_occurring_insertion_points`: per-type quick-scan toggles (same list).
- `modifying_parameter_locations` **[gap, distinctive]**: test by *moving* a param
  between locations — `url_to_body`, `url_to_cookie`, `body_to_url`, `body_to_cookie`,
  `cookie_to_url`, `cookie_to_body`.
- `ignored_insertion_points`: `skip_all_tests_for_parameters`,
  `skip_server_side_injection_for_parameters` (name lists).
- `misc_insertion_point_options`: `max_insertion_points_per_base_request`,
  `use_nested_insertion_points`.
- `javascript_analysis` **[gap]**: `use_static_analysis`, `use_dynamic_analysis`,
  `max_static_time_per_item`, `max_dynamic_time_per_item`, `request_missing_dependencies`,
  `fetch_out_of_scope_resources`.
- `issues_reported`: scan-type gates — `scan_type_passive`, `scan_type_light_active`,
  `scan_type_medium_active`, `scan_type_intrusive_active`, `scan_type_javascript_analysis`;
  or `select_individual_issues` + `selected_issues` (per-issue-type on/off).
- `error_handling`: consecutive-failure thresholds to skip insertion point / fail item /
  pause task.

**Issue catalog:** 368 types, hex `typeIndex` taxonomy (families: `0010` injection,
`0020` client-side/request, `0040`, `0050`, `0060`, …). Each: name, description,
remediation, typicalSeverity, references, vulnerabilityClassifications (CWE). ferrite
must author its own text; the taxonomy and CWE mapping are facts to mirror.

**Built-in presets** (`BuiltInConfigs`, 29): Crawl+Audit Fast/Balanced/Deep/Lightweight/
CICD; coverage thorough/maximum; crawl strategy faster…most complete; crawl time limits;
minimize false positives/negatives; audit passive-only / BChecks-only / critical-only /
light / medium; never-stop-on-errors. Each is a sparse overlay on the defaults.

---

## E. Sequencer (randomness analysis)  **[part]** `src/sequencer.rs`

`live_capture`: `num_threads`, `throttle`, `max_length_deviation`,
`ignore_abnormal_length_tokens`. `token_analysis` (FIPS + statistical tests):
`fips_monobit`, `fips_poker`, `fips_runs`, `fips_long_run`, `spectral`, `correlation`,
`compression`, `count`, `transitions`. `token_handling`: `base_64_decode_before_analyzing`,
`pad_short_tokens_at` (start/end), `pad_with`. Verify which tests ferrite implements.

---

## F. Sessions / auth

`sessions.cookie_jar`: per-tool monitor flags (proxy on by default; repeater, intruder,
scanner, sequencer, extender, ai off). `sessions.macros.macros` (recorded request
sequences). `sessions.session_handling_rules.rules` (scoped rule engine: run macro,
extract token, set cookie, invoke extension action). **[part]** `src/session.rs`,
`src/macros.rs`, `src/browser_auth.rs` — the scoped pre-send rule engine is the key piece.

Platform authentication (`connections.platform_authentication`): HTTP Basic/NTLM/Digest
credential sets. Client certs (`ssl.client_certificates`) **[?]**.

---

## G. Connections / transport

`socks_proxy` (host/port/auth, `dns_over_socks`, bypass list) **[gap]**.
`upstream_proxy.servers` (per-host upstream HTTP proxy) **[part, races/groups ref]**.
`timeouts`: `connect_timeout`, `normal_timeout`, `open_ended_response_timeout`,
`domain_name_resolution_timeout`, `failed_domain_name_resolution_timeout`.
`dns.hostname_resolution` (static host overrides), `lookup_policy`.

`project_options.http`: `redirections.understand_{3xx,any_status_with_location,
javascript_driven,meta_refresh_tag,refresh_header}`; `status_100_responses`
(understand/remove 100-continue); `streaming_responses` (SSE: `store`,
`strip_chunked_encoding_metadata`, `use_text_event_stream_header`, scoped urls);
`http1.enable_keep_alive`, `http2.enable_http2`.

`ssl.negotiation`: `enabled_protocols`, `enabled_ciphers`, `tls_negotiation_behavior`,
`allow_unsafe_renegotiation`, `disable_ssl_session_resume`, `disable_sni_extension`,
`enable_blocked_algorithms`, `enforce_upstream_trust`. **[?]** — relevant to ferrite's
fingerprint/evasion surface.

---

## H. Resource pools (rate control)  **[part]** `src/work.rs`, `src/rules.rs`

Per-pool: `concurrent_request_limit` (+enabled), `throttle_interval_millis` (+enabled),
`throttle_random` (+enabled), `auto_backoff` on 429 / 503 / custom status codes. Scanner
and intruder bind to a pool. ferrite references resource pools in intruder; confirm
backoff + throttle exist.

---

## I. Logger / history / organizer / target  **[part]**

Capture + display filters on every table (by mime type, status class, tool, scope,
search term, file extension, annotation), memory limits, `filter_mode`. **Bambda** [gap]:
a Java/JS-expression filter DSL (`return true;`) over http history, logger, sitemap, WS
history — more powerful than ferrite's `src/search.rs` text filter. Organizer item
status workflow: new / in_progress / postponed / done / ignored **[have]**
`src/organizer.rs`. Comparer `sync_views` **[have]** `src/comparer.rs`.

---

## J. Client-side browser tools (plain JS — technique fully visible)

- **DOM Invader** (`resources/Browser/DomInvader/js/`: `dom-invader.js`, `postmessage.js`,
  `shared.js`, `settings.js`, `devtools.js`): instruments the DOM to find client-side XSS,
  DOM-based sink flows, postMessage bugs, prototype pollution via a canary string. ferrite
  has `assets/dom-probe.js` + `src/browser_lab.rs` **[part]** — DOM Invader is the fuller
  version to mirror (canary propagation through sources→sinks).
- **Clickbandit** (`resources/Clickbandit/clickbandit.js`) **[gap]**: records a clickjacking
  attack and emits a PoC HTML page.
- **Navigation Recorder** (`resources/Browser/NavigationRecorder/`, a Chrome extension
  service worker) **[part]** `src/browser_auth.rs`: records a login/navigation sequence for
  authenticated crawling.

---

## K. Platform / misc

Burp **REST API** (`user_options.misc.api`: port 1337, loopback/all, API keys,
insecure_mode) **[gap]** — note ferrite's `src/api_import.rs` is the opposite (imports
OpenAPI specs). Hotkeys: 50 default bindings **[gap]**. Auto project backup (interval,
in-scope-only, delete-on-shutdown). Embedded browser settings (data dir, GPU, sandbox).
Message-editor configs (request/response view tabs), inspector widgets, uninteresting-header
hiding (22 request / 27 response headers). AI (`project_options.ai` / `user_options.ai`) —
out of scope for ferrite.

---

## L. What only dynamic analysis reveals

Static RE gives the config surface and API contracts above; the *algorithms* are
Zelix-encrypted. Recover by running Burp under its bundled JRE
(`/nix/store/0gfys…-burpsuite.jar`) and Frida-hooking the JVM
(REA `start_frida_session` / `instrument_with_frida`) one feature at a time:
- Crawl heuristics (how `dom_idle`/`network_idle` thresholds drive the headless browser).
- Audit insertion-point mutation + how `modifying_parameter_locations` is applied.
- HTTP/2 multiplexing and race last-byte-sync timing.
- CA minting and per-host leaf cert generation.
- Collaborator payload format and polling protocol on the wire.

Name a feature and it can be traced live.
