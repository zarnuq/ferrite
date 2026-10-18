# Ferrite regression tests

Run the default suite:

```sh
sh scripts/test-regressions.sh
```

Include the isolated headless Chromium tests:

```sh
FERRITE_BROWSER_TESTS=1 sh scripts/test-regressions.sh
```

The runner continues to browser tests even if the default suite fails, and returns
nonzero if either stage fails. `FERRITE_TEST_THREADS` controls default concurrency
(default: 4); browser tests run serially. It does not launch the ignored external
HTTP test.

Equivalent commands:

```sh
cargo test --locked --offline -- --test-threads=4
cargo test --locked --offline browser_lab -- --include-ignored --test-threads=1
```

Use `cargo fetch --locked` first if the locked dependencies are not cached.
Python 3 is required for script-hook fixtures. Chromium is required only for the
opt-in browser tests. Local socket tests need loopback access outside Codex's
restricted network sandbox. These fixtures do not need an internet target, the
user's VPN target, or an existing Chromium profile.

## Coverage

Regression modules supplement the existing tests:

| Module | Contracts exercised |
| --- | --- |
| `src/robust_tests/api.rs` | OpenAPI parameter/body encoding, base overrides, local references, recursive schemas, Postman folders/variables, GraphQL types, WSDL escaping, malformed definitions, operation budgets |
| `src/robust_tests/workflows.rs` | Chained token extraction, login validity/refresh, binary requests and literal injection templates, cookie rotation, failure/origin boundaries, TCP connection reuse, parallel preparation failures, HTTP framing |
| `src/robust_tests/scripts.rs` | Script scoping, binary round trips, invalid output, process failures, timeout/output limits, package validation, passive controls, differential active checks |
| `src/robust_tests/transport.rs` | Individual HTTP/2 sends with cookies and binary evidence, group body/authority/hop-header handling, independent errors, oversized groups, TLS/ALPN, proxy streaming and WebSockets |
| `src/robust_tests/persistence.rs` | Snapshot independence, identity/workflow/scope isolation, binary persistence, corruption without partial restore, atomic writes, private permissions, retention |
| `src/tests/callbacks_regression.rs` | DNS parsing/truncation, HTTP/DNS listeners, correlation, stale events, caps, occupied ports, fragmented HTTP callbacks |
| `src/tests/browser_lab_regression.rs` | Fill/click replay, assertions, messages, recorder bindings, source/sink observations, dynamic DOM links, prototype evidence, cross-origin blocking, stale events |
| `src/tests/target_scope_regression.rs` | Actual right-click menu action using headless egui input, scope cache refresh, selected-host path filtering |
| `src/tests/scanner_regression.rs` | Nested JSON, multipart/header/cookie insertion points, binary upload preservation, framing, neutral/repeated controls, transient error rejection, deduplication after restore, session jar interaction |
| `src/tests/intruder_workflows.rs` | Saved plan isolation, unsent-only resume, uncertain delivery, retention-boundary checkpoints, payload processing |
| `src/authz.rs` | Original/anonymous/user wire isolation, exact-origin restrictions, main-jar independence, state-changing replay opt-in |
| `src/interactsh.rs` | Official JSON parsing, invalid output, endpoint announcement, mock CLI lifecycle/cancellation without public registration |
| `src/work.rs` | Shared concurrency, pause/cancel, shared response backoff |

Fixtures use ephemeral loopback ports, temporary directories and generated test
certificates. Servers are aborted on fixture drop; headless Chromium profiles are
closed and removed. Browser tests do not attach to or close the user's browser.
The test suite adds no new dependencies.

## Recorded result — 2026-10-17

- Default suite: **140 passed, 0 failed, 6 ignored** (146 discovered tests).
- The six ignored tests are five opt-in Chromium tests and the pre-existing
  external-target HTTP test. The browser command explicitly runs those five
  Chromium tests plus the browser stale-event regression.
- Browser-lab suite with ignored tests explicitly included: **6 passed, 0 failed**.
- `cargo check --locked --offline` and the release build pass without warnings.
- `git diff --check` passes.

The earlier eight failures are resolved: script EOF handling, GraphQL list
samples, API URL scheme validation, oversized HTTP/2 groups, incomplete response
framing and fragmented callback collection all retain active passing assertions.

See [workflow documentation](docs/WORKFLOWS.md) for feature entry points,
configuration examples and limits. Public Interactsh integration is tested with a
local fake CLI, not a live public registration. Visible recording uses the same
CDP recorder binding exercised headlessly; the desktop window itself was not
manually driven during automated verification.

This suite is regression coverage, not proof of complete Burp parity. Real-world
cross-origin SSO, abrupt power loss/disk exhaustion, public DNS delegation and
long-duration high-load operation remain outside this verification.
