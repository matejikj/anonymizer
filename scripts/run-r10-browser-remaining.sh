#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PLAYWRIGHT_BROWSERS_PATH=./.playwright-browsers
export MAX_SIZE_FULL=1
export MAX_SIZE_FIXTURE_DIR=tests/performance/fixtures/max-size
export MAX_SIZE_SKIP_BUILD=1

run_one() {
  local project=$1
  local target=$2
  echo "RUN $project $target"
  if npx playwright test --config=playwright.max-size-release.config.ts --retries=0 \
    "$target" --project="$project"; then
    echo "OK $project $target"
  else
    echo "FAIL $project $target"
  fi
  node scripts/collect-capacity-browser-runs.mjs
}

run_one firefox tests/performance/e2e/max-size-text-release.spec.ts:28
run_one webkit tests/performance/e2e/max-size-text-release.spec.ts:28
run_one chromium tests/performance/e2e/max-size-text-release.spec.ts:87
run_one firefox tests/performance/e2e/max-size-text-release.spec.ts:87
run_one webkit tests/performance/e2e/max-size-text-release.spec.ts:87
run_one firefox tests/performance/e2e/max-size-pcap-release.spec.ts:40
run_one webkit tests/performance/e2e/max-size-pcap-release.spec.ts:40
run_one firefox tests/performance/e2e/max-size-pcap-release.spec.ts:169
run_one webkit tests/performance/e2e/max-size-pcap-release.spec.ts:169
run_one chromium tests/performance/e2e/max-size-text-release.spec.ts:133
