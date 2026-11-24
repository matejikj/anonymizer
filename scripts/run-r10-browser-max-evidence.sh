#!/usr/bin/env bash
# R10/T46 — sequential MAX_SIZE_FULL browser capacity runs (survives partial progress).
set -euo pipefail
cd "$(dirname "$0")/.."
export PLAYWRIGHT_BROWSERS_PATH=./.playwright-browsers
export MAX_SIZE_FULL=1
export MAX_SIZE_FIXTURE_DIR=tests/performance/fixtures/max-size
export MAX_SIZE_SKIP_BUILD=1

LOG=tests/performance/results/r10-browser-max-evidence.log
mkdir -p tests/performance/results
: >"$LOG"

run_one() {
  local project=$1
  local target=$2
  echo "=== $(date -Iseconds) $project $target ===" | tee -a "$LOG"
  if npx playwright test --config=playwright.max-size-release.config.ts \
    "$target" --project="$project" >>"$LOG" 2>&1; then
    echo "OK $project $target" | tee -a "$LOG"
  else
    echo "FAIL $project $target (exit $?)" | tee -a "$LOG"
  fi
  node scripts/collect-capacity-browser-runs.mjs >>"$LOG" 2>&1 || true
}

if [[ ! -f tests/performance/fixtures/max-size/maximum-90mib-lf.log ]]; then
  npm run fixtures:max-size >>"$LOG" 2>&1 || true
fi

# Text 90 MiB
run_one chromium tests/performance/e2e/max-size-text-release.spec.ts:28
run_one firefox tests/performance/e2e/max-size-text-release.spec.ts:28
run_one webkit tests/performance/e2e/max-size-text-release.spec.ts:28
run_one chromium tests/performance/e2e/max-size-text-release.spec.ts:87
run_one firefox tests/performance/e2e/max-size-text-release.spec.ts:87
run_one webkit tests/performance/e2e/max-size-text-release.spec.ts:87

# PCAP 100 MiB
run_one chromium tests/performance/e2e/max-size-pcap-release.spec.ts:40
run_one firefox tests/performance/e2e/max-size-pcap-release.spec.ts:40
run_one webkit tests/performance/e2e/max-size-pcap-release.spec.ts:40
run_one chromium tests/performance/e2e/max-size-pcap-release.spec.ts:73
run_one chromium tests/performance/e2e/max-size-pcap-release.spec.ts:169
run_one firefox tests/performance/e2e/max-size-pcap-release.spec.ts:169
run_one webkit tests/performance/e2e/max-size-pcap-release.spec.ts:169
run_one chromium tests/performance/e2e/max-size-text-release.spec.ts:133
run_one chromium tests/performance/e2e/max-size-pcap-release.spec.ts:103

echo "=== DONE $(date -Iseconds) ===" | tee -a "$LOG"
node scripts/collect-capacity-browser-runs.mjs | tee -a "$LOG"
