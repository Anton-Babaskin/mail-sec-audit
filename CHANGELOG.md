# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic
versioning where practical.

## [Unreleased]

## [3.0.0] - 2026-11-02

The audit core is rewritten in Python 3.9+ (standard library only). The 2.3
Bash script was used as the list of requirements; every check is mapped in
`docs/check-mapping.md`. Background: `docs/review-2026-11.md`,
`docs/adr/0001-architecture.md`.

### Breaking

- Python 3.9 or newer is required (previously optional). `mail-sec-audit.sh`
  exits with 69 and a clear message when it is missing.
- `--format json` now emits the FleetOps `HealthResult` document
  (`schema_version "1.0"`, `host`, `collected_at`, `duration_ms`,
  `overall_status`, `checks[]`). The 2.3 document is available as
  `--format json-v1`.
- Finding IDs are stable check names (`SSH.X11_FORWARDING`,
  `TLS.CERT_EXPIRY@465`) instead of positional `SSH-004`, which changed
  whenever an earlier check fired.
- New exit code 75 when another audit holds the lock; signals exit with
  128+N. Codes 0, 1, 2, 64, 69 and 73 keep their meaning; UNKNOWN results
  give 1.

### Added

- Statuses `UNKNOWN` (with a reason: permission, missing tool, timeout,
  truncation, no data, parse error, internal error) and `N/A`. One failing
  check no longer stops the report.
- Evidence, source and next step for every finding; data-source and probe
  lists in every report.
- `--lang ru|en`; all human-readable text comes from two catalogs.
- Platform adapters: Mail-in-a-Box, Mailcow, iRedMail, generic (Postfix,
  Exim, OpenSMTPD, Sendmail; Dovecot, Courier).
- Checks: effective Postfix relay restrictions for port 25 with master.cf
  overrides and rule order, broad mynetworks, OpenSMTPD and Sendmail relay
  from configuration files, Dovecot minimum TLS protocol, TLS 1.1 next to TLS
  1.0 in `--deep`, MX record, revoked DKIM keys, kernel newer than the running
  one, container health of the compose project.
- Single-file build `dist/mail-sec-audit.pyz` (`tools/build_zipapp.py`).
- Example reports in `examples/`.

### Changed

- Every external command goes through an allowlisted runner with timeouts
  and output limits; no shell. `docker exec` inner commands are checked.
- Missing permissions, tools or data no longer produce OK or FAIL
  (`sshd -T`, firewall, Fail2ban, journal, DNF).
- Firewall: Docker chains and Fail2ban ban chains are not a host firewall.
- Listeners: DHCP client sockets ignored; platform ports expected.
- Postfix statistics: structural field parsing, loopback content-filter hops
  not counted as external deliveries, Mailcow syslog names, memory bounded by
  messages in flight; mail auth uses `rip=` only and ignores aborted logins.
- Timestamps only at line start; syslog year from the file mtime; Docker
  nanosecond timestamps on Python 3.9/3.10.
- DNS keeps the response code: SERVFAIL and timeouts are UNKNOWN; TXT strings
  are joined without spaces.
- Queue size via `postqueue -j` (long queue IDs).
- `--redact` validates IP addresses (clock times stay readable) and also hides
  host names, the mail domain and local account names; statistics use keyed
  per-run pseudonyms.
- Reports are written through the descriptor opened with `O_EXCL|O_NOFOLLOW`;
  append refuses hard links and group/other-writable files; text reports never
  contain ANSI colors. `--interactive` works together with `--report`.
- Interactive mode protects every established SSH session, not only
  `SSH_CONNECTION`.
- Non-security package updates are INFO; security updates WARN.

### Removed

- `lib/mail_stats.py` and the Bash implementation of the checks.
- The separate YUM branch (on EL8+ `yum` is DNF; EL7 is unsupported).
- Progress messages that were exported as INFO findings.
- Reading `/etc/shadow` hashes (replaced by `passwd -S`).

### Security

- Includes the fixes from 2.3.1 and 2.3.2 (no execution of the Mail-in-a-Box
  wrapper, isolated Python, signal handling, no `sendmail -bv`,
  `rpm -Va --noscripts`).

## [2.3.2] - 2026-11-02

### Security

- Every embedded `python3` call runs in isolated mode (`-I`). `python3 -` and
  `python3 -c` put the current directory first on `sys.path`, so an
  `ipaddress.py` or `json.py` in the directory the audit was started from ran
  with root privileges.
- `HUP`, `INT` and `TERM` now stop the audit with status 129/130/143. The old
  trap removed the temporary directory and let the script continue, which
  produced a report from missing files.
- The Sendmail branch reads `/etc/mail/sendmail.mc` instead of running
  `sendmail -d0.1 -bv root`. With Postfix's `sendmail` binary `-bv` sends a
  verification report by mail, and other `/usr/sbin/sendmail` providers may
  wait for a message on stdin.
- `--deep` runs `rpm -Va --noscripts`; without it RPM executes each package's
  `%verifyscript` as root.
- `dnf check-update` writes its logs into the private temporary directory
  instead of `/var/log/dnf*.log`.

## [2.3.1] - 2026-11-02

### Security

- Mail-in-a-Box detection no longer runs `mailinabox --version`. The
  `/usr/local/bin/mailinabox` wrapper ignores arguments and sources
  `setup/start.sh`, so the read-only audit started the Mail-in-a-Box setup
  (including `setup/migrate.py --migrate`). The version is now read with
  `git describe` from the setup checkout named in the wrapper, without
  executing it.
- `tests/forbidden_commands.sh` fails CI if the script calls `mailinabox` or
  Mailcow `update.sh`, using a static scan and exported-function interception
  (a PATH shim cannot work because the script resets PATH).

## [2.3.0] - 2026-08-20

### Added

- Mailcow, iRedMail, and Mail-in-a-Box platform detection and collection
  adapters, including Mailcow container logs and configuration commands.
- Exact inclusive `--from`/`--to` periods and Postfix Queue ID analytics for
  authenticated users, envelope senders, top domains, deliveries, and bytes.
- Filesystem/inode reporting and platform-aware mailbox storage capacity.
- Structured JSON reports with stable finding IDs, remediation hints,
  filesystem data, mail statistics, and optional redaction.
- DNS checks for MTA-STS, TLS-RPT, multiple SPF records, DMARC policy, and DKIM
  public-key size.
- Deterministic Postfix fixtures and parser/redaction regression tests.
- Repository maintenance files for consistent editing, licensing, security
  reporting, contribution flow, and CI checks.
- Modern bilingual README pages and a project structure guide.
- `--version` output and CLI regression coverage for invalid or incomplete
  options.

### Changed

- Version advanced to 2.3.0; Python 3 is used for structured traffic analytics
  and JSON while the main system auditor remains Bash.
- CI now covers Ubuntu 22.04 and 24.04, compiles the Python parser, and pins
  Node.js 24-based checkout v6 to a full commit SHA without persisted credentials.
- Reports are created without overwrite at mode `0600`; appending is explicit,
  owner-checked, text-only, and symbolic-link targets are rejected.
- CLI values, audit periods, mail statistics limits, and additional public
  ports are validated before the audit starts.

### Fixed

- Authentication log counts are filtered to the selected period, including
  rotated host logs and iRedMail Dovecot logs.
- IP validation fails closed for IPv6 without Python and rejects non-global
  targets before interactive Fail2ban actions.
- Missing option values no longer leave the argument parser in an infinite
  loop.
- TLS probe output files now use the current probe's port and STARTTLS mode.
- ShellCheck findings that caused every GitHub Actions CI run to fail.
