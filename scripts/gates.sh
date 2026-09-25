#!/usr/bin/env bash
# T-344 (Agent 26) - local equivalent of the CI gate set, POSIX/Linux/macOS.
# Same gates, same order as .github/workflows/ci.yml and scripts/gates.ps1:
#   rust.fmt / rust.test / rust.clippy
#   app.typecheck / app.test / app.build / app.ui
#   py.secret_scan / py.copy_overlap / py.check_fixtures / py.check_csp /
#   py.check_encoding / py.compose_static
# Every gate prints PASS, FAIL or SKIP plus a trailing summary line, and the
# script exits non-zero if any gate FAILs. SKIP is reserved for genuinely
# absent tooling (no cargo / no node / no python / no headless browser) and
# never for a check that ran and failed.
#   ./scripts/gates.sh                  # every gate, CI order
#   GATES_ONLY=rust,py ./scripts/gates.sh
#   GATES_ONLY=app.ui ./scripts/gates.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

ONLY="${GATES_ONLY:-}"
FAILED=""
SKIPPED=""
RESULTS=""
RAN=0

selected() { # key
  [ -z "$ONLY" ] && return 0
  local token
  IFS=',' read -ra tokens <<< "$ONLY"
  for token in "${tokens[@]}"; do
    token="$(printf '%s' "$token" | tr '[:upper:]' '[:lower:]' | xargs)"
    [ -n "$token" ] || continue
    case "$1" in "$token"*) return 0 ;; esac
  done
  return 1
}

have() { command -v "$1" >/dev/null 2>&1; }

record() { # key status [note]
  local key="$1" status="$2" note="${3:-}"
  RESULTS="${RESULTS}${status} ${key}"
  [ -n "$note" ] && RESULTS="${RESULTS} (${note})"
  RESULTS="${RESULTS}"$'\n'
  case "$status" in
    PASS) printf 'PASS  %s\n' "$key" ;;
    FAIL) printf 'FAIL  %s - %s\n' "$key" "$note" ;;
    *)    printf 'SKIP  %s - %s\n' "$key" "$note" ;;
  esac
}

header() { RAN=$((RAN + 1)); printf '\n== [%s] %s ==\n' "$RAN" "$1"; }

gate() { # key title cmd...
  local key="$1" title="$2"; shift 2
  selected "$key" || return 0
  header "$title"
  "$@"
  local rc=$?
  if [ $rc -eq 0 ]; then record "$key" PASS; else record "$key" FAIL "exit $rc"; FAILED="${FAILED}${key} "; fi
}

tool_gate() { # key title tool reason cmd...
  local key="$1" title="$2" tool="$3" reason="$4"; shift 4
  selected "$key" || return 0
  if ! have "$tool"; then
    header "$title"
    record "$key" SKIP "$reason"
    SKIPPED="${SKIPPED}${key} "
    return 0
  fi
  gate "$key" "$title" "$@"
}

find_browser() {
  local bin
  for bin in google-chrome google-chrome-stable chromium chromium-browser; do
    if have "$bin"; then command -v "$bin"; return 0; fi
  done
  local hit
  hit="$(ls -1 "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux/chrome 2>/dev/null | head -n 1 || true)"
  [ -n "$hit" ] && { printf '%s\n' "$hit"; return 0; }
  return 1
}

printf 'gates.sh - repo root: %s\n' "$ROOT"
[ -n "$ONLY" ] && printf 'filter: %s\n' "$ONLY"

tool_gate rust.fmt "cargo fmt --all -- --check" cargo "cargo not on PATH" \
  cargo fmt --all -- --check
tool_gate rust.test "cargo test --workspace" cargo "cargo not on PATH" \
  cargo test --workspace
tool_gate rust.clippy "cargo clippy --workspace --all-targets -- -D warnings" cargo "cargo not on PATH" \
  cargo clippy --workspace --all-targets -- -D warnings

tool_gate app.typecheck "kiwi-app: npm run typecheck" npm "npm not on PATH" \
  npm --prefix kiwi-app run typecheck
tool_gate app.test "kiwi-app: npm test" npm "npm not on PATH" \
  npm --prefix kiwi-app test
tool_gate app.build "kiwi-app: npm run build" npm "npm not on PATH" \
  npm --prefix kiwi-app run build

if selected app.ui; then
  header "kiwi-app: npm run test:ui (CDP browser smoke)"
  if ! have npm; then
    record app.ui SKIP "npm not on PATH"
    SKIPPED="${SKIPPED}app.ui "
  elif BROWSER="$(find_browser)"; then
    printf 'browser: %s\n' "$BROWSER"
    KIWI_SMOKE_BROWSER="$BROWSER" npm --prefix kiwi-app run test:ui
    rc=$?
    if [ $rc -eq 0 ]; then record app.ui PASS; else record app.ui FAIL "exit $rc"; FAILED="${FAILED}app.ui "; fi
  else
    record app.ui SKIP "no headless browser found (chrome/chromium); suite reports SKIP, never PASS"
    SKIPPED="${SKIPPED}app.ui "
  fi
fi

tool_gate py.secret_scan "python tests/tools/secret_scan.py" python "python not on PATH" \
  python tests/tools/secret_scan.py
tool_gate py.copy_overlap "python tests/tools/copy_overlap.py" python "python not on PATH" \
  python tests/tools/copy_overlap.py
tool_gate py.check_fixtures "python tests/tools/check_fixtures.py" python "python not on PATH" \
  python tests/tools/check_fixtures.py
tool_gate py.check_csp "python tests/tools/check_csp.py" python "python not on PATH" \
  python tests/tools/check_csp.py
tool_gate py.check_encoding "python tests/tools/check_encoding.py" python "python not on PATH" \
  python tests/tools/check_encoding.py
tool_gate py.compose_static "python -m unittest tests.infra.test_compose.ComposeStaticTests" python "python not on PATH" \
  python -m unittest tests.infra.test_compose.ComposeStaticTests

printf '\n=== gate summary ===\n'
printf '%s' "$RESULTS" | grep -v '^$'
PASS_COUNT="$(printf '%s' "$RESULTS" | grep -c '^PASS ' || true)"
FAIL_COUNT="$(printf '%s' "$RESULTS" | grep -c '^FAIL ' || true)"
SKIP_COUNT="$(printf '%s' "$RESULTS" | grep -c '^SKIP ' || true)"
SUMMARY="gates: ${RAN} run, ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${SKIP_COUNT} SKIP"
if [ "$FAIL_COUNT" -gt 0 ]; then
  SUMMARY="${SUMMARY} - failed: $(printf '%s' "$FAILED" | sed 's/ $//')"
  printf '%s\n' "$SUMMARY"
  exit 1
fi
printf '%s\n' "$SUMMARY"

if [ "$RAN" -eq 0 ]; then
  printf "no gate matched GATES_ONLY=%s\n" "$ONLY"
  exit 2
fi
exit 0
