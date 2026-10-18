# ferrite

A Burp Suite-style intercepting proxy for web app pentesting, written in Rust with an egui UI.

## Features

Pick tools from the **View** dropdown (top left):

- **Proxy** — HTTP/1.1, HTTP/2, WebSockets, TLS MITM with a generated CA; history with
  status filters, notes, timestamps; Intercept (requests, responses, WebSocket messages);
  Match & replace; scope; TLS pass-through; upstream HTTP/SOCKS5 proxy.
- **Manual tools** — Repeater (tabs, Inspector, history, HTTP/2 groups), WebSocket Repeater,
  Intruder (all four attack types, processors, grep/extract, lazy dispatch), Sequencer,
  Decoder, Comparer, Organizer.
- **Automated** — passive and active scanner (plus deep-scan differential probes), Crawler,
  content Discovery, race-condition tester, authorization comparison across identities,
  API import (OpenAPI, Postman, GraphQL, WSDL), public callbacks via Interactsh.
- **Browser** — Open Chromium button (dedicated profile, CA trusted automatically),
  Browser Lab recording/replay and browser-auth session capture.
- **Sessions** — cookie jar, per-user identities, login macros.
- **Logger, Search, Reports, Dashboard, Extensions** (Python SDK in `sdk/`, example in
  `examples/extensions/`).
- **Projects** — save/load `.ferrite` files, autosave on exit, HAR import/export.

See [docs/WORKFLOWS.md](docs/WORKFLOWS.md) for how to use the workflow features and
[plan.md](plan.md) for the development history.

## Build and run

```sh
cargo build --release --locked
target/release/ferrite [LISTEN_ADDR]   # default 127.0.0.1:8080
```

The CA (`ca.pem`) and settings live in `~/.config/ferrite`. Import the CA into your browser
and point its proxy at the listen address, or use **Open Chromium**.

## Install (Gentoo)

A live ebuild is in the [zarnuq overlay](https://github.com/zarnuq/gentoo-overlay)
(`net-proxy/ferrite`). It installs the binary, desktop entry and icon.

```sh
eselect repository add zarnuq git https://github.com/zarnuq/gentoo-overlay.git
emaint sync -r zarnuq
emerge net-proxy/ferrite
```

On other distros, copy `assets/ferrite.desktop` to `~/.local/share/applications/` and
`assets/ferrite.svg` to `~/.local/share/icons/hicolor/scalable/apps/`.

## Tests

```sh
sh scripts/test-regressions.sh                          # default suite
FERRITE_BROWSER_TESTS=1 sh scripts/test-regressions.sh  # plus headless Chromium tests
```

Details in [TESTING.md](TESTING.md).
