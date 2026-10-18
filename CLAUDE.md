# ferrite

Burp-style intercepting proxy, Rust + egui (`eframe` 0.37), `hudsucker` for MITM. See README.md.

## Layout

- `src/main.rs` — app state, `Tab` enum, `Event` (runtime → UI) and `Action` (cross-tab) enums,
  module list. Each tool is one module in `src/`.
- Tests: `src/*_tests.rs`, `src/robust_tests/`, `src/tests/`; `#[cfg(test)] mod hardening`.
- `assets/` — `dom-probe.js` (Browser Lab), `ferrite.desktop` + `ferrite.svg` (menu entry and icon; names must match
  the `with_app_id("ferrite")` in main.rs).
- `sdk/ferrite_sdk.py` + `examples/extensions/` — Python extension API.
- `plan.md` — full session-by-session history and decisions. `TESTING.md` — test runner and
  last recorded results. `docs/WORKFLOWS.md` — user-facing workflow docs.

## Commands

```sh
cargo test --locked --offline -- --test-threads=4
sh scripts/test-regressions.sh             # FERRITE_BROWSER_TESTS=1 for Chromium tests
cargo build --release --locked --offline
```

Socket fixture tests need loopback access (fail with PermissionDenied in a sandbox).
One ignored test hits an external target. `cargo fmt --check` has pre-existing diffs.

## Gentoo ebuild

Live ebuild: `/home/miles/Projects/gentoo-overlay/net-proxy/ferrite/ferrite-9999.ebuild`
(repo github.com/zarnuq/gentoo-overlay, synced to `/var/db/repos/zarnuq`).
Update it when install-time files, runtime deps, or the Rust edition/MSRV change. It installs
the cargo binary, `assets/ferrite.desktop` (`domenu`) and `assets/ferrite.svg` (`doicon`).

## Recent changes

- `5e6c14b` — authorization comparison, Browser Lab, callbacks/Interactsh, macros, API import,
  repeater groups, extensions, robust regression suites, TESTING.md and docs/WORKFLOWS.md.
- `f82a699` — Races tab, browser-auth session capture, deep-scan differential probes, coalesced
  HTTP/2 frame flushing for race groups, hardening tests, extension SDK example.
- Desktop entry + SVG icon added (`assets/`), installed by the ebuild.
