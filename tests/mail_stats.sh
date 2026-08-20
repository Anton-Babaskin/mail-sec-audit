#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
analyzer="${repo_root}/lib/mail_stats.py"
fixture="${repo_root}/tests/fixtures/postfix-mail.txt"
test_root="$(mktemp -d /tmp/mail-sec-audit-test.XXXXXX)"
cleanup() {
  if [[ "$test_root" == /tmp/mail-sec-audit-test.* && -d "$test_root" && ! -L "$test_root" ]]; then
    rm -rf -- "$test_root"
  fi
}
trap cleanup EXIT

python3 "$analyzer" \
  --input "$fixture" \
  --from '2026-08-17 00:00:00' \
  --to '2026-08-17 23:59:59' \
  --top 10 \
  --json-output "$test_root/stats.json" \
  --output-dir "$test_root/tables"

python3 - "$test_root/stats.json" "$repo_root" <<'PY'
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[2]) / "lib"))

from mail_stats import parse_timestamp

data = json.load(open(sys.argv[1], encoding="utf-8"))
totals = data["totals"]
assert totals["outbound_messages"] == 3, totals
assert totals["authenticated_submissions"] == 4, totals
assert totals["authenticated_outbound_messages"] == 3, totals
assert totals["outbound_deliveries"] == 4, totals
assert totals["incoming_messages"] == 1, totals
assert totals["incoming_deliveries"] == 1, totals
assert totals["bounced_deliveries"] == 1, totals
assert totals["deferred_deliveries"] == 1, totals
assert totals["outbound_bytes"] == 3500, totals

users = {row["address"]: row for row in data["top_users"]}
assert users["bob@example.com"]["messages"] == 2, users
assert users["alice@example.com"]["submitted"] == 2, users
assert users["alice@example.com"]["deliveries"] == 2, users
sender_domains = {row["domain"]: row["count"] for row in data["top_sender_domains"]}
recipient_domains = {row["domain"]: row["count"] for row in data["top_recipient_domains"]}
assert sender_domains["example.com"] == 3, sender_domains
assert recipient_domains == {"one.net": 2, "two.net": 2}, recipient_domains
assert data["period"]["observed_to"].startswith("2026-08-17"), data["period"]
assert parse_timestamp("Aug 17 10:00:00 mail postfix/qmgr[1]: ABCDE: removed", dt.datetime(2026, 8, 18)) == dt.datetime(2026, 8, 17, 10)
assert parse_timestamp("Dec 31 23:59:59 mail postfix/qmgr[1]: ABCDE: removed", dt.datetime(2026, 1, 1)) == dt.datetime(2025, 12, 31, 23, 59, 59)
PY

python3 "$analyzer" \
  --input "$fixture" \
  --from '2026-08-17 00:00:00' \
  --to '2026-08-17 23:59:59' \
  --top 10 \
  --redact \
  --json-output "$test_root/redacted.json"

if grep -Eq 'alice@example\.com|bob@example\.com|one\.net|two\.net' "$test_root/redacted.json"; then
  echo "Redacted report leaked a mailbox or domain" >&2
  exit 1
fi

echo "Mail statistics checks passed."
