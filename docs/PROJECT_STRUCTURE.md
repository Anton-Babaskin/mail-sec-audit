# Project Structure

```text
.
├── mail-sec-audit.sh        # entry point: checks Python 3.9+, runs the package with -I
├── mail_sec_audit/
│   ├── cli.py               # options, limits, exit 64; no check logic
│   ├── app.py               # lock, signals, temp dir, checks, rendering, exit code
│   ├── runner.py            # the only place that starts processes (allowlist)
│   ├── model.py             # Status, Finding, Evidence, Completeness, Report
│   ├── host.py              # file system, clock, identity (replaceable in tests)
│   ├── safefile.py          # report files and the single-instance lock
│   ├── interactive.py       # Fail2ban menu, the only mutating mode
│   ├── facts/               # collection, one module per source
│   ├── logs/                # sources, timestamps, Postfix/Dovecot/sshd parsing, statistics
│   ├── rules/               # one check per module
│   ├── stacks/              # mailinabox, mailcow, iredmail, generic
│   ├── render/              # terminal, json (FleetOps HealthResult), json-v1, redaction
│   └── i18n/                # en and ru catalogs
├── tests/
│   ├── unit/                # unit tests
│   ├── e2e/                 # scenario tests per stack and host
│   ├── helpers.py           # fake runner, fixture trees, scenario runner
│   └── *.sh                 # CLI contract and wrapper checks
├── tools/
│   ├── build_zipapp.py      # dist/mail-sec-audit.pyz
│   └── make_examples.py     # regenerates examples/
├── examples/                # example reports from a synthetic scenario
├── docs/
│   ├── review-2026-11.md    # review of 2.3 with confirmations
│   ├── adr/0001-architecture.md
│   ├── check-mapping.md     # every 2.3 check → new ID or removal
│   ├── USAGE.md, SECURITY_MODEL.md, DEVELOPMENT.md
├── CLAUDE.md                # rules for coding agents
├── README.md, README_RU.md, CHANGELOG.md, SECURITY.md, CONTRIBUTING.md, LICENSE
└── pyproject.toml           # ruff and mypy configuration only
```

Generated reports and `dist/` are ignored by git: audit output can contain
sensitive operational data.
