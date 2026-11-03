# Usage Guide

## Running

```bash
sudo bash mail-sec-audit.sh [options]
```

`mail-sec-audit.sh` checks for Python 3.9+ and runs the `mail_sec_audit`
package in isolated mode (`python3 -I`). Keep the script and the package
together, or use the single file `dist/mail-sec-audit.pyz` built with
`python3 tools/build_zipapp.py`:

```bash
sudo python3 -I mail-sec-audit.pyz [options]
```

Root is recommended. Without root, checks that need it return `UNKNOWN`
with the reason (permission denied), never `OK`.

## Period

`--from` and `--to` are inclusive local calendar days. With only `--to`,
`--days` (default 7) counts back from it. Without either, the period starts
`--days` days before today at 00:00 and ends now.

```bash
sudo bash mail-sec-audit.sh --from 2026-08-01 --to 2026-08-07 --mail-top 30
```

Logs are read only for that period: files older than the start are skipped,
rotated `.gz` files are streamed, syslog lines without a year get the year
from the file modification time.

## Mail statistics (Postfix)

Counted separately:

| Field | Meaning |
|---|---|
| `outbound_messages` | messages with at least one successful external delivery |
| `outbound_deliveries` | successful external recipient deliveries |
| `deferred_deliveries`, `bounced_deliveries` | delivery attempts with that status (a later success is counted too) |
| `internal_hops` | hand-offs to a loopback content filter (amavis etc.); not external deliveries |
| `incoming_messages`, `incoming_deliveries` | local deliveries (lmtp/local/virtual/pipe) |
| `authenticated_submissions` | messages submitted with SASL authentication |
| `outbound_bytes` | queue size of delivered messages |

The sender, size and SASL user carry over a content-filter hop through the
`queued as` reference. Watchdog health checks of Mailcow are ignored.

## Platform override

Auto-detection is normal. Override only for unusual layouts:

```bash
sudo bash mail-sec-audit.sh --platform mailcow
sudo bash mail-sec-audit.sh --platform iredmail
sudo bash mail-sec-audit.sh --platform mailinabox
sudo bash mail-sec-audit.sh --platform generic
```

## DNS and TLS identity

```bash
sudo bash mail-sec-audit.sh --hostname mail.example.com --domain example.com --dkim-selector mail
```

DNS queries (via `dig`) are sent only with `--domain`. TLS probes connect to
the local addresses of listeners on 25, 465, 587, 993, 995, 143, 110 and 443;
every probe is listed in the report. `--deep` also offers TLS 1.0 and 1.1;
if this Python/OpenSSL cannot offer them, the result is `UNKNOWN`.

## Reports

```bash
sudo bash mail-sec-audit.sh --report /root/reports/audit.txt
sudo bash mail-sec-audit.sh --format json --redact --report /root/reports/audit.json
sudo bash mail-sec-audit.sh --format json-v1 --report /root/reports/audit-v1.json
sudo bash mail-sec-audit.sh --append-report /root/reports/audit.log
```

- `--report` creates a new file (mode 0600); an existing path or a symlink is
  refused (exit 73). The text report has no ANSI colors.
- `--append-report` needs an existing regular file owned by you, with one link
  and no group/other write permission. Text only.
- `--format json` is the FleetOps HealthResult; `--format json-v1` is the 2.3
  layout.

### Redaction

`--redact` replaces e-mail addresses, IPv4/IPv6 addresses, the audited host
names and mail domain (with subdomains) and local account names (UID ≥ 1000).
Mailbox and domain names in statistics become pseudonyms keyed per run (stable
inside one report, not linkable across reports). Not covered: third-party host
names in evidence (remote relays, PTR names), certificate subjects of other
names, device paths. Review a report before sharing it.

## Interactive Fail2ban menu

```bash
sudo bash mail-sec-audit.sh --interactive
```

Opens after the report, only with a terminal and as root. Actions show the
exact command and need `BAN`/`UNBAN` typed. Refused addresses: invalid,
non-global, this host's own, and any address with an established SSH session.
Each change is logged with `logger -t mail-sec-audit`.

## Allowed public ports

```bash
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" bash mail-sec-audit.sh
```

Decimal ports 1-65535 only. Standard mail, web and DNS ports and the SSH port
from `sshd -T` are expected by default; platform ports (e.g. 12340 on
Mail-in-a-Box) come from the platform adapter.
