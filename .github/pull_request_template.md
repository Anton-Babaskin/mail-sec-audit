## Summary

- 

## Safety

- [ ] Default audit mode remains read-only.
- [ ] Any write action is explicit and confirmed by the user.
- [ ] No sensitive logs, reports, IP lists, or credentials are included.

## Checks

- [ ] `bash -n mail-sec-audit.sh`
- [ ] `bash tests/smoke.sh`
- [ ] `shellcheck mail-sec-audit.sh tests/*.sh`

