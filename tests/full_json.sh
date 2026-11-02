#!/usr/bin/env bash
# Runs the real audit on the CI host (read-only, not a mail server) and
# checks the JSON documents against the FleetOps HealthResult field names
# (--format json) and the 2.3 layout (--format json-v1).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d /tmp/mail-sec-audit-json-test.XXXXXX)"
cleanup() {
  if [[ "$test_root" == /tmp/mail-sec-audit-json-test.* && -d "$test_root" && ! -L "$test_root" ]]; then
    rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT
version_line="$(bash "$repo_root/mail-sec-audit.sh" --version)"
expected_version="${version_line##* }"

for format in json json-v1; do
  report_file="$test_root/audit-$format.json"
  set +e
  output="$(timeout 300 bash "$repo_root/mail-sec-audit.sh" --days 1 --format "$format" --redact --no-color --report "$report_file")"
  status=$?
  set -e
  case "$status" in
    0|1|2) ;;
    *) printf 'Audit (--format %s) exited unexpectedly with %d\n' "$format" "$status" >&2; exit "$status" ;;
  esac
  [[ "$(stat -c %a "$report_file")" == "600" ]] || { echo "report mode is not 0600" >&2; exit 1; }
  python3 -I -c '
import json, sys
data = json.load(sys.stdin)
saved = json.load(open(sys.argv[1], encoding="utf-8"))
assert data == saved, "stdout and saved report differ"
fmt, version, status = sys.argv[2], sys.argv[3], int(sys.argv[4])
if fmt == "json":
    assert set(data) == {"schema_version", "host", "collected_at", "duration_ms", "overall_status", "checks"}, set(data)
    assert data["schema_version"] == "1.0"
    assert data["host"]["hostname"] == "<redacted-host>"
    assert data["overall_status"] in ("ok", "warning", "critical", "unknown")
    fields = {"name", "status", "summary", "metrics", "reason", "error", "timed_out", "duration_ms", "raw_ref"}
    for check in data["checks"]:
        assert set(check) == fields, check
        assert check["summary"] and check["duration_ms"] >= 0
    audit = next(c for c in data["checks"] if c["name"] == "CTX.AUDIT")
    assert audit["metrics"]["version"] == version
    count, overall = len(data["checks"]), data["overall_status"]
    print(f"--format json: {count} checks, overall {overall}")
else:
    assert data["schema_version"] == 1 and data["tool"]["version"] == version
    assert data["result"]["exit_code"] == status
    assert isinstance(data["findings"], list) and isinstance(data["filesystems"], list)
    count = len(data["findings"])
    print(f"--format json-v1: {count} findings, exit {status}")
' "$report_file" "$format" "$expected_version" "$status" <<<"$output"
done
