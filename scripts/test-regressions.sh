#!/bin/sh
# All default tests use local fixtures. Browser tests are opt-in and also local.
set -u
cd -- "$(dirname -- "$0")/.." || exit 1
ferrite_test_status=0
cargo test --locked --offline -- --test-threads="${FERRITE_TEST_THREADS:-4}" || ferrite_test_status=1
if [ "${FERRITE_BROWSER_TESTS:-0}" = 1 ]; then
    cargo test --locked --offline browser_lab -- --include-ignored --test-threads=1 || ferrite_test_status=1
fi
exit "$ferrite_test_status"
