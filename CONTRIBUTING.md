# Contributing

Thank you for helping improve Mail Security Audit.

## Scope

A read-only security and health audit for Linux mail servers, written in
Python 3.9+ with the standard library only. Delivery analysis of single
messages belongs to [miab-radar](https://github.com/Anton-Babaskin/miab-radar).

## Workflow

1. Create a feature branch; one stage per branch and pull request.
2. Follow [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and [CLAUDE.md](CLAUDE.md).
3. Run the checks on Linux (WSL2 or a container):

   ```bash
   python3 -m unittest discover -s tests -t .
   bash tests/smoke.sh && bash tests/wrapper.sh
   ruff check . && mypy && shellcheck mail-sec-audit.sh tests/*.sh
   ```

4. Update both READMEs and the docs when behaviour, options or guarantees change.

## Pull request checklist

- The default audit stays read-only; new commands are allowlist entries with a test.
- Missing data gives UNKNOWN, not OK; non-applicable checks give N/A.
- New texts exist in both catalogs (en, ru).
- No real domains, addresses, Message-IDs or credentials in fixtures or examples.
