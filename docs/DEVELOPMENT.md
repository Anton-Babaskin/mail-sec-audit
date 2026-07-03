# Development

## Requirements

- Bash 5 or newer
- Linux test environment for full runtime checks
- ShellCheck for static analysis

## Local checks

```bash
bash -n mail-sec-audit.sh
bash tests/smoke.sh
shellcheck mail-sec-audit.sh tests/*.sh
```

## Repository layout

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for the expected repository
layout and where new documentation, examples, and tests should go.

## Release checklist

1. Update `VERSION` in `mail-sec-audit.sh`.
2. Update `CHANGELOG.md`.
3. Verify README examples still match the script flags.
4. Run syntax and ShellCheck checks.
5. Create a signed tag when possible.
