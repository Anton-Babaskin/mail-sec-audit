# Development

## Requirements

- Bash 5 or newer on Linux
- Python 3.10 or newer
- ShellCheck

## Local checks

```bash
bash -n mail-sec-audit.sh tests/*.sh
python3 -m py_compile lib/mail_stats.py
bash tests/smoke.sh
bash tests/full_json.sh
shellcheck mail-sec-audit.sh tests/*.sh
```

`tests/mail_stats.sh` uses a deterministic Postfix fixture to verify Queue ID
correlation, exact dates, top-user/domain counters and redaction. Add sanitized
fixtures whenever supporting a new log format or platform version.

CI runs the same checks on Ubuntu 22.04 and 24.04. Third-party GitHub Actions
are pinned to a full commit SHA.

## Design boundaries

- Keep the default audit read-only and time-bound every network/container call.
- Parse untrusted logs as data; do not evaluate or source them.
- Add mutating operations only behind explicit interactive confirmation.
- Keep stable finding IDs and backwards-compatible JSON fields where possible.
- Treat text redaction as best-effort and test structured redaction separately.

## Release checklist

1. Update `VERSION` and `CHANGELOG.md`.
2. Verify English/Russian examples and JSON schema compatibility.
3. Add fixtures for new parser behavior.
4. Run all local checks and one full text/JSON audit on Linux.
5. Review the diff for secrets and generated reports.
6. Create a signed tag when possible.
