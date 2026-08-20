#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${repo_root}/mail-sec-audit.sh"

bash -n "$script"

fail() {
  echo "$1" >&2
  exit 1
}

expect_status() {
  local expected="$1" description="$2"
  shift 2
  local actual output

  set +e
  output="$(timeout 2 bash "$script" "$@" 2>&1)"
  actual=$?
  set -e

  if (( actual != expected )); then
    printf 'Expected %s to exit %d, got %d. Output:\n%s\n' \
      "$description" "$expected" "$actual" "$output" >&2
    exit 1
  fi
}

help_output="$(bash "$script" --help)"
[[ -n "$help_output" ]] || fail "Expected --help to print usage output"

grep -q -- "--days" <<<"$help_output" || fail "Expected --help output to mention --days"

version_output="$(bash "$script" --version)"
[[ "$version_output" =~ ^mail-sec-audit\ [0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "Expected --version to print a semantic version"

for option in --hostname --domain --dkim-selector --from --to --platform --format --report --append-report; do
  expect_status 64 "$option without a value" "$option"
done

expect_status 64 "an option used as --hostname value" --hostname --deep
expect_status 64 "zero --days" --days 0
expect_status 64 "oversized --days" --days 999999999999999999999999
expect_status 64 "out-of-range --mail-top" --mail-top 101
expect_status 64 "invalid --from date" --from 2026-02-31
expect_status 64 "reversed period" --from 2026-08-18 --to 2026-08-17
expect_status 64 "unknown platform" --platform exchange
expect_status 64 "unknown output format" --format yaml
expect_status 64 "JSON append is invalid" --format json --append-report /tmp/unused-mail-audit.json
expect_status 64 "JSON interactive mode is invalid" --format json --interactive
expect_status 64 "duplicate report destinations" --report /tmp/one --report /tmp/two
expect_status 64 "unknown option" --does-not-exist

for ports in '443 invalid' '70000'; do
  set +e
  ports_output="$(MAIL_AUDIT_ALLOWED_PORTS="$ports" timeout 2 bash "$script" --no-color 2>&1)"
  ports_status=$?
  set -e
  if (( ports_status != 64 )); then
    printf 'Expected invalid MAIL_AUDIT_ALLOWED_PORTS=%s to exit 64, got %d. Output:\n%s\n' \
      "$ports" "$ports_status" "$ports_output" >&2
    exit 1
  fi
done

report_test_root="$(mktemp -d /tmp/mail-sec-audit-report-test.XXXXXX)"
cleanup_report_test() {
  if [[ "$report_test_root" == /tmp/mail-sec-audit-report-test.* && -d "$report_test_root" && ! -L "$report_test_root" ]]; then
    rm -rf -- "$report_test_root"
  fi
}
trap cleanup_report_test EXIT
: >"$report_test_root/existing.log"
ln -s "$report_test_root/existing.log" "$report_test_root/symlink.log"
expect_status 73 "existing --report target" --report "$report_test_root/existing.log"
expect_status 73 "symlink --report target" --report "$report_test_root/symlink.log"

bash "$repo_root/tests/mail_stats.sh"

echo "Smoke checks passed."
