<div align="center">

# 🛡️ Mail Security Audit

### Read-only security and health audit for Linux mail servers, in one command

<img src="https://img.shields.io/badge/version-3.0.0-2563eb?style=for-the-badge" alt="Version 3.0.0">
<img src="https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+">
<img src="https://img.shields.io/badge/default-read--only-16a34a?style=for-the-badge" alt="Read-only by default">
<img src="https://img.shields.io/github/license/Anton-Babaskin/mail-sec-audit?style=for-the-badge&color=0ea5e9" alt="License">

<a href="README_RU.md">Русский</a> · <a href="#quick-start">Quick start</a> · <a href="#what-it-checks">Checks</a> · <a href="#results-and-exit-codes">Results</a> · <a href="#safety-model">Safety</a>

</div>

---

## Quick start

```bash
git clone https://github.com/Anton-Babaskin/mail-sec-audit.git
cd mail-sec-audit
sudo bash mail-sec-audit.sh
```

The script runs the `mail_sec_audit` package next to it with the system
Python 3.9 or newer in isolated mode. No packages are installed and nothing
is downloaded. A single-file build is available too:

```bash
python3 tools/build_zipapp.py          # creates dist/mail-sec-audit.pyz
sudo python3 -I dist/mail-sec-audit.pyz --domain example.org
```

## Supported platforms

| Platform | How it is audited |
|---|---|
| Mail-in-a-Box | Postfix/Dovecot on the host, `/var/log/mail.log` in both line formats, version from the setup checkout via `git describe`. **The `mailinabox` command is never run** (it starts the setup). |
| Mailcow | Docker: `docker ps/inspect/logs`, `postconf`, `doveconf`, `postqueue` through `docker exec`; postscreen on port 25; netfilter container as brute-force protection. `mailcow.conf` and `update.sh` are never touched. |
| iRedMail | Host Postfix/Dovecot, Dovecot logs in `/var/log/dovecot/`, amavis hops recognised. |
| Generic Postfix | Files or journald (including `postfix@-.service`). |
| Exim, OpenSMTPD, Sendmail | Detection, service state, relay heuristics and queue size. Mail statistics are Postfix only. |

Distributions: Debian 11+, Ubuntu 22.04+, RHEL/Rocky/Alma 9 (system Python is
3.9+). RHEL 8 needs the `python39` package; CentOS/RHEL 7 is not supported.

## What it checks

- **Updates and reboot**: pending security updates (APT/DNF), APT list age,
  automatic updates, reboot marker and running vs installed kernel.
- **Mail platform**: MTA and IMAP detection, required services and containers,
  container health.
- **SSH**: effective `sshd -T` values (root login, passwords, keys, X11,
  MaxAuthTries), authorized_keys ownership and permissions.
- **Exposure**: non-loopback listeners outside the expected ports, host
  firewall that actually drops by default (Docker chains do not count),
  Fail2ban/CrowdSec/sshguard/stack protection.
- **Authentication events**: SSH and mail authentication failures with top
  source addresses.
- **Mail flow (Postfix)**: messages, deliveries, attempts, bounces/deferrals,
  top users, senders and domains; content-filter hops are not counted twice and
  hostile log fields cannot fake results.
- **Relay**: Postfix restrictions for port 25 including master.cf overrides
  and rule order, mynetworks; Exim, OpenSMTPD and Sendmail relay settings.
- **TLS**: local handshake, certificate expiry and name, Dovecot minimum
  protocol; with `--deep`, TLS 1.0/1.1 acceptance.
- **DNS** (with `--domain`): MX, SPF, DMARC, DKIM and key size, MTA-STS,
  TLS-RPT, PTR, with response codes (SERVFAIL is not "missing").
- **Host hygiene**: UID 0, accounts without passwords (`passwd -S`, hashes are
  never read), sudo NOPASSWD, disk and inodes, SUID files, world-writable paths,
  failed units, AppArmor/SELinux, cron and timers, backup indicators, logins;
  `--deep` package integrity and recently modified files.

The full list with stable IDs is in [docs/check-mapping.md](docs/check-mapping.md).

## Results and exit codes

Every finding has a stable ID (`SSH.ROOT_LOGIN`, `TLS.CERT_EXPIRY@465`), a
status, the source it came from, evidence and a next step.

| Status | Meaning |
|---|---|
| `OK` | checked and fine |
| `INFO` | inventory or context, no action needed |
| `WARN` | review recommended |
| `FAIL` | critical |
| `UNKNOWN` | could not be checked: no permission, missing tool, timeout, truncated or unreadable data. The reason is given. Never counted as OK. |
| `N/A` | not applicable on this host or not requested (e.g. DNS without `--domain`) |

| Exit code | Meaning |
|---:|---|
| `0` | no WARN, FAIL or UNKNOWN |
| `1` | WARN or UNKNOWN, no FAIL |
| `2` | at least one FAIL |
| `64` | invalid command line |
| `69` | Python 3.9+ not available |
| `73` | the report file could not be created or appended safely |
| `75` | another audit is already running |
| `128+N` | stopped by signal N (130 for Ctrl+C) |

## Usage examples

```bash
# period, identity and DNS
sudo bash mail-sec-audit.sh --from 2026-08-01 --to 2026-08-07 \
  --hostname mail.example.com --domain example.com --dkim-selector mail

# machine-readable report (FleetOps HealthResult), redacted, new private file
sudo bash mail-sec-audit.sh --format json --redact --report /root/audit.json

# the 2.3 JSON layout for existing consumers
sudo bash mail-sec-audit.sh --format json-v1 --report /root/audit-v1.json

# slower checks, Russian output
sudo bash mail-sec-audit.sh --deep --lang ru

# allow monitoring ports as expected public listeners
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" bash mail-sec-audit.sh
```

Example reports generated from the synthetic test scenario are in
[examples/](examples/).

All options: `bash mail-sec-audit.sh --help`. Details: [docs/USAGE.md](docs/USAGE.md).

## JSON

`--format json` emits the FleetOps `HealthResult` document: `schema_version`
(`"1.0"`), `host{id, hostname}`, `collected_at`, `duration_ms`,
`overall_status` (`ok`/`warning`/`critical`/`unknown`) and `checks[]` with
`name`, `status`, `summary`, `metrics`, `reason`, `error`, `timed_out`,
`duration_ms`, `raw_ref`. The native status, section, source, evidence and
next step of each finding are in `metrics`; tool version, period and probes
are in the `CTX.AUDIT` check, Postfix statistics in `FLOW.STATISTICS`,
filesystems in `DISK.FILESYSTEMS`. `host.id` is a hash derived from
`/etc/machine-id`; the machine-id itself is not published.

`--format json-v1` keeps the 2.3 document (`schema_version: 1`) with the same
field names, plus additive fields.

## Safety model

- The audit is read-only. The only mode that changes anything is
  `--interactive` (Fail2ban ban/unban, each action typed `BAN`/`UNBAN`).
  Addresses of this host, of every open SSH session and non-global addresses
  are refused.
- Every external command goes through one runner with an allowlist of argument
  shapes, a timeout and an output limit; no shell is used. `mailinabox` and
  `update.sh` are refused with any arguments; `docker` is limited to `ps`,
  `inspect`, `logs` and `exec` without options, with the inner command checked
  against the same list.
- Secrets are not read: password hashes, private keys, `sasl_passwd`,
  `mailcow.conf`, message bodies. `doveconf` is never called with `-x`.
- Network: TLS probes go only to local listener addresses; DNS is queried only
  with `--domain`. Both are listed in the report.
- Reports are created with `O_EXCL|O_NOFOLLOW` and mode 0600; existing files
  and symlinks are refused. Temporary files live in a private directory that is
  removed on exit and on signals.

More: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Related projects

- [miab-radar](https://github.com/Anton-Babaskin/miab-radar): delivery diagnostics for Mail-in-a-Box (per-message analysis, DNSBL).
- [smtp-egress-audit](https://github.com/Anton-Babaskin/smtp-egress-audit): attribution of outbound SMTP connections.
- [FleetOps](https://github.com/Anton-Babaskin/FleetOps): consumes the `--format json` HealthResult.

## License

MIT, see [LICENSE](LICENSE).
