# Project Structure

This repository keeps the production script at the root and supporting project
files in predictable directories.

```text
.
├── mail-sec-audit.sh
├── README.md
├── README_RU.md
├── docs/
├── examples/
├── tests/
├── .github/
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
└── LICENSE
```

## Root files

- `mail-sec-audit.sh` is the main executable audit script.
- `README.md` is the default English project page.
- `README_RU.md` mirrors the main README in Russian.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md` define
  repository policy and maintenance flow.

## Supporting directories

- `docs/` contains deeper guides that would make the README too long.
- `examples/` contains safe copyable configuration snippets.
- `tests/` contains lightweight checks suitable for local use and CI.
- `.github/` contains GitHub Actions, issue templates, and the pull request
  template.

## Generated files

Generated reports and local environment files are intentionally ignored by git
because audit output can include sensitive operational data.

