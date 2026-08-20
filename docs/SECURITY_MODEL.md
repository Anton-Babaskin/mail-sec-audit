# Security Model

Mail Security Audit inspects local server state and reports findings without
changing production configuration in its default mode.

## Read-only default

The normal audit does not change firewall rules, restart services, install
packages, modify mail/SSH configuration, delete queued mail, or change bans.
It does create a private temporary directory and, when requested, a report.
Package checks use simulation or cache-only modes where supported.

Mailcow support invokes only read operations such as `docker logs`,
`docker inspect`, `postconf`, `postqueue` and `doveconf`.

## Interactive boundary

`--interactive` is the only system-changing workflow. Fail2ban ban/unban
operations require confirmation. The script rejects malformed, non-global,
host-owned and current SSH client addresses; IPv6 actions fail closed when a
reliable Python address parser is unavailable.

This protection reduces operator error but is not a replacement for console
access, a second administrative session and a tested rollback procedure.

## Files and sensitive output

- the process uses a fixed administrative `PATH`, `LC_ALL=C` and `umask 077`;
- temporary cleanup is restricted to the expected private path prefix;
- `--report` refuses overwrites and symbolic-link targets;
- reports are mode `0600`;
- `--append-report` requires an existing regular file owned by the current UID;
- JSON append is prohibited because concatenated documents are invalid.

Create reports only in a trusted directory that unprivileged users cannot
rename or write into; path checks do not make an attacker-controlled parent
directory safe from filesystem races.

Audit output can expose hostnames, addresses, usernames, domains, open ports and
traffic patterns. `--redact` masks common email/IP forms and pseudonymizes mail
statistics, but it is best-effort rather than a formal data-loss-prevention
system. Review reports before transferring them off-host.

## Trust assumptions and limits

The tool assumes the local root environment, kernel, utilities, Docker daemon
and inspected log files have not been maliciously subverted. A compromised
host can lie to a local auditor. Local configuration inspection also cannot
prove the absence of open relay or validate Internet-path TLS behavior; those
checks require a separate external probe.

Log statistics depend on retention and format. Queue IDs may theoretically be
reused across very long log windows, and bounce/deferred numbers count delivery
events, not necessarily unique messages.
