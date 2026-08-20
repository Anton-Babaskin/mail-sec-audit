# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic
versioning where practical.

## [Unreleased]

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
