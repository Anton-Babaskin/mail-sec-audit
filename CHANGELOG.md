# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic
versioning where practical.

## [Unreleased]

### Added

- New Python 3.9+ core in `mail_sec_audit/` (standard library only): allowlisted command runner with
  timeouts and output limits, OK/INFO/WARN/FAIL/UNKNOWN/N/A model with stable IDs, evidence and
  completeness, ru/en catalogs, terminal, JSON v1 and FleetOps renderers, private report files,
  single-instance lock, signal handling and a zipapp build. Not yet the entry point.

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
