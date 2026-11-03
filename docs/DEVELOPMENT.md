# Development

## Requirements

- Linux (WSL2 or a container on Windows; Git Bash is not a test environment)
- Python 3.9+ for running; tests use only the standard library
- Development tools: `ruff`, `mypy` (strict), `shellcheck`

## Checks

```bash
python3 -m unittest discover -s tests -t .
bash tests/smoke.sh
bash tests/wrapper.sh
bash tests/full_json.sh          # runs the real audit on this machine, read-only
ruff check . && ruff format --check mail_sec_audit tests tools
mypy                             # strict, configured in pyproject.toml
shellcheck mail-sec-audit.sh tests/*.sh
python3 tools/build_zipapp.py && python3 -I dist/mail-sec-audit.pyz --version
```

CI runs the unit and scenario tests on Python 3.9 and 3.10, ruff and mypy,
the shell tests on Ubuntu 22.04 and 24.04, and everything again in an
`ubuntu:22.04` container with the system Python and without gawk.

## Layout

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) and
[ADR 0001](adr/0001-architecture.md).

## Rules for changes

- Default mode stays read-only. Anything that changes the system belongs to
  `--interactive`, behind confirmation.
- A new external command is a new `Rule` in `runner.RULES` with a `why`, a
  timeout and an output limit, plus a test in `tests/unit/test_runner.py`.
- One check per module in `mail_sec_audit/rules/`, registered in
  `rules/__init__.py`; the module name equals the check ID
  (`SSH.ROOT_LOGIN` → `ssh_root_login.py`).
- Rules read facts (`ctx.facts`) and never start processes or test the stack
  name. Stack differences go to `mail_sec_audit/stacks/`.
- No data means `UNKNOWN` with a reason; not applicable means `N/A`.
- Every human-readable text is a key in both `i18n/en.py` and `i18n/ru.py`;
  tests check identical keys and placeholders and render every finding of every
  scenario strictly in both languages.
- Fixtures use `.example` domains and documentation IP ranges only. Real log
  shapes go to `tests/fixtures/shapes/<stack>/` after removing customer data;
  formats without a real sample are marked as assumptions in the test.

## Tests

- `tests/unit/`: runner allowlist and process limits, CLI, report files and
  lock, signals, catalogs, renderers (FleetOps field contract, JSON v1
  mapping, escaping, redaction), log parsing with hostile lines, TLS prober
  against loopback servers, interactive menu, zipapp, static rules.
- `tests/e2e/`: full audits per scenario with `tests.helpers.run_scenario`
  (fake runner that enforces the real allowlist, fixture file tree, fixed
  clock and identity, fake TLS prober).
- `tests/*.sh`: the Bash entry point and the CLI contract.

## Release checklist

1. Update `mail_sec_audit/__init__.py` (`__version__`) and `CHANGELOG.md`.
2. Regenerate examples: `TZ=UTC python3 tools/make_examples.py`.
3. Run all checks above on Linux and at least one audit on a real server of
   each supported platform.
4. Build `dist/mail-sec-audit.pyz` and attach it to the release.
5. Review the diff for secrets and real hostnames.
