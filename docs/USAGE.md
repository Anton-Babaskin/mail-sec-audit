# Usage Guide

## Basic run

Run the repository as a unit because the Bash entry point uses
`lib/mail_stats.py` for Postfix analytics and JSON output.

```bash
sudo ./mail-sec-audit.sh
```

Root is recommended for complete logs, Docker state, firewall rules and mail
configuration. The default run is read-only.

## Periods and traffic statistics

`--from` and `--to` are inclusive local calendar dates:

```bash
sudo ./mail-sec-audit.sh \
  --from 2026-08-01 \
  --to 2026-08-07 \
  --mail-top 30
```

If only `--to` is supplied, `--days` determines how far back the period starts.
If neither exact bound is supplied, the default is the preceding seven days.

Postfix statistics distinguish authenticated submissions, unique delivered
messages and recipient deliveries. One message addressed to three recipients
is one message and three deliveries. Results are limited by readable retained
logs and Postfix Queue ID correlation.

## Platform adapters

Auto-detection is the normal choice. Use an override only for unusual layouts:

```bash
sudo ./mail-sec-audit.sh --platform mailcow
sudo ./mail-sec-audit.sh --platform iredmail
sudo ./mail-sec-audit.sh --platform mailinabox
```

The Mailcow adapter reads Postfix and Dovecot container logs and executes
read-only configuration/queue commands inside their containers. iRedMail and
Mail-in-a-Box use their conventional host log and mailbox-storage locations.

## DNS and TLS identity

```bash
sudo ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector default
```

## Reports

Create a new private text report:

```bash
sudo ./mail-sec-audit.sh --report /root/reports/audit-2026-08-07.txt
```

Create a redacted machine-readable report:

```bash
sudo ./mail-sec-audit.sh \
  --format json --redact \
  --report /root/reports/audit-2026-08-07.json
```

`--report` refuses an existing path or symlink and creates a mode `0600` file.
`--append-report` is explicit and text-only. Redaction is best-effort: inspect a
report before sharing it because free-form configuration output can contain
site-specific identifiers. Use a root-owned report directory that is not
writable by unprivileged users.

## Allow known public monitoring ports

```bash
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" ./mail-sec-audit.sh
```

Only decimal TCP port numbers from 1 through 65535 are accepted.
