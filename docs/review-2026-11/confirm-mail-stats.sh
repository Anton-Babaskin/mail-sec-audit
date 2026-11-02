#!/usr/bin/env bash
# Hostile and edge-case log lines against lib/mail_stats.py (main @ 33f2d51).
set -u
REPO="${1:?usage: $0 /path/to/checkout-of-33f2d51}"
OUT="$(mktemp -d /tmp/msa-review.XXXXXX)"
py39="${PYTHON39:-python3.9}"

stats() { # fixture file -> totals
  local py="$1" fixture="$2"
  "$py" "$REPO/lib/mail_stats.py" --input "$fixture" --from '2026-08-17 00:00:00' --to '2026-08-17 23:59:59' \
    --json-output "$OUT/out.json" >/dev/null && "$py" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d["totals"], sort_keys=True)); print("users:", [u["address"] for u in d["top_users"]])' "$OUT/out.json"
}

echo "== H1 sasl_username= inside a hostile envelope sender marks the message as authenticated =="
cat >"$OUT/h1.log" <<'EOF'
2026-08-17T10:00:00Z mail postfix/smtpd[1]: 4AB12C3D4E: client=unknown[203.0.113.9]
2026-08-17T10:00:01Z mail postfix/qmgr[2]: 4AB12C3D4E: from=<"sasl_username=ceo"@attacker.example>, size=100, nrcpt=1 (queue active)
2026-08-17T10:00:02Z mail postfix/smtp[3]: 4AB12C3D4E: to=<victim@remote.example>, relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)
EOF
stats python3 "$OUT/h1.log"

echo "== H2 status=sent inside a quoted recipient overrides the real status=bounced =="
cat >"$OUT/h2.log" <<'EOF'
2026-08-17T10:00:01Z mail postfix/qmgr[2]: 5BC23D4E5F: from=<user@example.org>, size=100, nrcpt=1 (queue active)
2026-08-17T10:00:02Z mail postfix/smtp[3]: 5BC23D4E5F: to=<"x status=sent"@remote.example>, relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=5.1.1, status=bounced (550 no such user)
EOF
stats python3 "$OUT/h2.log"

echo "== H3 size= inside a hostile sender replaces the real size =="
cat >"$OUT/h3.log" <<'EOF'
2026-08-17T10:00:01Z mail postfix/qmgr[2]: 6CD34E5F6A: from=<"size=999999999"@attacker.example>, size=100, nrcpt=1 (queue active)
2026-08-17T10:00:02Z mail postfix/smtp[3]: 6CD34E5F6A: to=<a@remote.example>, relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)
EOF
stats python3 "$OUT/h3.log"

echo "== H4 loopback content-filter hop is counted as external delivery (double count) =="
cat >"$OUT/h4.log" <<'EOF'
2026-08-17T10:00:00Z mail postfix/submission/smtpd[1]: 7DE45F6A7B: client=unknown[192.0.2.10], sasl_method=PLAIN, sasl_username=alice@example.org
2026-08-17T10:00:01Z mail postfix/qmgr[2]: 7DE45F6A7B: from=<alice@example.org>, size=1000, nrcpt=1 (queue active)
2026-08-17T10:00:02Z mail postfix/smtp[3]: 7DE45F6A7B: to=<bob@remote.example>, relay=127.0.0.1[127.0.0.1]:10024, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 8EF56A7B8C)
2026-08-17T10:00:03Z mail postfix/qmgr[2]: 8EF56A7B8C: from=<alice@example.org>, size=1400, nrcpt=1 (queue active)
2026-08-17T10:00:04Z mail postfix/smtp[4]: 8EF56A7B8C: to=<bob@remote.example>, relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)
EOF
stats python3 "$OUT/h4.log"

echo "== H5 'warning:' is accepted as a Queue ID and receives a SASL user =="
cat >"$OUT/h5.log" <<'EOF'
2026-08-17T10:00:00Z mail postfix/smtpd[1]: warning: unknown[203.0.113.9]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=admin
EOF
stats python3 "$OUT/h5.log"

echo "== H6 Docker nanosecond timestamps are dropped on Python 3.9 =="
cat >"$OUT/h6.log" <<'EOF'
2026-08-17T10:00:01.123456789Z postfix/qmgr[2]: 9FA67B8C9D: from=<user@example.org>, size=100, nrcpt=1 (queue active)
2026-08-17T10:00:02.123456789Z postfix/smtp[3]: 9FA67B8C9D: to=<a@remote.example>, relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)
EOF
echo "python3.9:"; stats "$py39" "$OUT/h6.log"
echo "python3 ($(python3 -V)):"; stats python3 "$OUT/h6.log"

echo "== H7 year inference uses the current year for old rotated lines =="
python3 - "$REPO/lib" <<'EOF'
import datetime as dt, sys
sys.path.insert(0, sys.argv[1])
from mail_stats import parse_timestamp
now = dt.datetime(2026, 11, 2, 12, 0)
# A line from a rotated file written in November 2025 (within a --days 400 window).
print("Nov  1 line, now=2026-11-02 ->", parse_timestamp("Nov  1 10:00:00 mail postfix/qmgr[1]: X: removed", now))
EOF

echo "== H8 timestamp is searched anywhere in the first 96 chars =="
python3 - "$REPO/lib" <<'EOF'
import datetime as dt, sys
sys.path.insert(0, sys.argv[1])
from mail_stats import parse_timestamp
line = "garbage-without-time postfix/smtpd[1]: helo=<2026-08-17T10:00:00Z> injected"
print("unparsable line receives time ->", parse_timestamp(line, dt.datetime(2026, 11, 2)))
EOF
