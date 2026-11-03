## Summary

- 

## Safety

- [ ] Default audit mode remains read-only; new commands are allowlist entries with a test.
- [ ] Missing data gives UNKNOWN with a reason; non-applicable checks give N/A.
- [ ] New texts are in both catalogs (en, ru).
- [ ] No real domains, addresses, logs, reports or credentials are included.

## Checks (Linux)

- [ ] `python3 -m unittest discover -s tests -t .`
- [ ] `bash tests/smoke.sh && bash tests/wrapper.sh`
- [ ] `ruff check . && mypy`
- [ ] `shellcheck mail-sec-audit.sh tests/*.sh`
