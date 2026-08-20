#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d /tmp/mail-sec-audit-json-test.XXXXXX)"
cleanup() {
  if [[ "$test_root" == /tmp/mail-sec-audit-json-test.* && -d "$test_root" && ! -L "$test_root" ]]; then
    rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT
report_file="$test_root/audit.json"

set +e
json_output="$(timeout 180 bash "$repo_root/mail-sec-audit.sh" --days 1 --format json --redact --no-color --report "$report_file")"
audit_status=$?
set -e

case "$audit_status" in
  0|1|2) ;;
  *)
    printf 'Full JSON audit exited unexpectedly with %d\n' "$audit_status" >&2
    exit "$audit_status"
    ;;
esac

[[ "$(stat -c %a "$report_file")" == "600" ]] || { echo "JSON report mode is not 0600" >&2; exit 1; }

python3 -c '
import json
import sys

data = json.load(sys.stdin)
saved = json.load(open(sys.argv[1], encoding="utf-8"))
assert data == saved, "stdout and saved report differ"
assert data["schema_version"] == 1, data
assert data["tool"]["version"] == "2.3.0", data["tool"]
assert isinstance(data["findings"], list), data
assert isinstance(data["filesystems"], list), data
assert data["result"]["exit_code"] in (0, 1, 2), data["result"]
print(f"Full JSON check passed ({len(data['"'"'findings'"'"'])} findings).")
' "$report_file" <<<"$json_output"
