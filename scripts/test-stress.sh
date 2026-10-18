#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")/.."
cargo test --locked --offline hardening::tests::sustained_proxy_load -- --ignored --exact --nocapture
