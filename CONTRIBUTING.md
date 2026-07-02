# Contributing

Thank you for helping improve Mail Security Audit.

## Scope

This project is a Bash-based audit tool for Linux mail servers. Contributions
should preserve the default read-only behavior and avoid surprising changes to
firewall, SSH, DNS, or mail server configuration.

## Development workflow

1. Fork the repository and create a feature branch.
2. Keep changes focused and documented.
3. Run local checks before opening a pull request:

   ```bash
   bash -n mail-sec-audit.sh
   bash tests/smoke.sh
   shellcheck mail-sec-audit.sh tests/*.sh
   ```

4. Update README or docs when behavior, flags, or safety guarantees change.

## Pull request checklist

- The script still runs in read-only mode by default.
- New write operations require explicit user confirmation.
- Shell syntax checks pass.
- User-facing output is clear and actionable.
- Sensitive data such as domains, IPs, logs, and credentials is not committed.

