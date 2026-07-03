# Mail Security Audit

<p align="center">
  <strong>Read-only security and operations audit for Linux mail servers.</strong>
</p>

<p align="center">
  Postfix · Exim · Dovecot · Fail2ban · UFW · nftables · TLS · DNS · Mail Logs
</p>

<p align="center">
  <a href="https://github.com/Anton-Babaskin/mail-sec-audit/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Anton-Babaskin/mail-sec-audit/ci.yml?branch=main&label=CI" alt="CI">
  </a>
  <img src="https://img.shields.io/badge/Bash-5%2B-4EAA25?logo=gnubash&logoColor=white" alt="Bash 5+">
  <img src="https://img.shields.io/badge/Linux-Debian%20%7C%20Ubuntu-FCC624?logo=linux&logoColor=black" alt="Debian and Ubuntu">
  <img src="https://img.shields.io/badge/Mode-read--only%20by%20default-2ea44f" alt="Read-only by default">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README_RU.md">Русский</a>
</p>

---

## Overview

**Mail Security Audit** is a single-file Bash tool for checking the security posture and operational health of Linux mail servers. It detects the installed mail stack, reviews SSH and firewall exposure, analyzes authentication failures, checks TLS and DNS, inspects mail queues, and summarizes findings in a clear terminal report.

The default mode is safe for production diagnostics: it reads system state and prints findings. It does not change firewall rules, restart services, install packages, edit mail server configuration, or automatically block IP addresses.

## What It Checks

| Area | Coverage |
|---|---|
| System health | OS, kernel, pending updates, reboot-required state, failed services, disk and inode usage |
| SSH security | Effective `sshd` settings, root login, password auth, SSH keys, successful and failed logins |
| Network exposure | Listening ports, public services, unexpected ports, database ports exposed externally |
| Firewall | UFW, nftables, iptables policies, Fail2ban firewall chains |
| Brute-force defense | Fail2ban jails and counters, CrowdSec and sshguard detection, safe manual ban menu |
| Mail stack | Postfix, Exim, Sendmail, OpenSMTPD, Dovecot, Courier detection |
| Mail auth | Dovecot and Postfix SASL failures, top attacking IPv4 and IPv6 addresses |
| Mail flow | Postfix sender and recipient domain statistics, delivery stats, Queue ID correlation |
| Queue state | Postfix and Exim queue size, deferred mail, warning thresholds |
| Relay safety | Postfix relay restrictions, `mynetworks`, `reject_unauth_destination`, Exim relay hints |
| TLS | HTTPS, SMTP, IMAP, POP3 STARTTLS, certificate identity, issuer, expiry, legacy TLS in deep mode |
| DNS | MX, SPF, DMARC, DKIM selector, PTR, mail hostname validation |
| Integrity | SUID/SGID checks, world-writable files, package integrity, cron, timers, backup tooling |

## Quick Start

Clone the repository and run the script on the mail server:

```bash
git clone https://github.com/Anton-Babaskin/mail-sec-audit.git
cd mail-sec-audit
chmod 700 mail-sec-audit.sh
sudo ./mail-sec-audit.sh
```

Run a domain-aware audit:

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector default
```

Save a local report:

```bash
sudo ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com \
  --report ./reports/mail-audit-$(date +%F).log
```

Reports may contain sensitive operational data. The `reports/` directory is ignored by git.

## Options

| Option | Description |
|---|---|
| `--days N` | Analyze logs for the last `N` days. Default: `7` |
| `--hostname HOST` | Mail server FQDN used for TLS checks |
| `--domain DOMAIN` | Primary mail domain used for DNS checks |
| `--dkim-selector NAME` | DKIM selector for DNS lookup |
| `--mail-top N` | Number of sender and recipient domains to display. Default: `20` |
| `--verbose` | Show extended diagnostic output |
| `--interactive` | Open the manual Fail2ban IP management menu |
| `--deep` | Run slower and more detailed checks |
| `--report FILE` | Save audit output to a file |
| `--no-color` | Disable ANSI colors |
| `-h`, `--help` | Print help |

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Audit completed without warnings or critical findings |
| `1` | One or more warnings were found |
| `2` | One or more critical findings were found |

## Safety Model

Normal audit mode does not:

- modify firewall rules;
- restart services;
- install packages;
- change SSH, Postfix, Exim, Dovecot, or DNS configuration;
- delete mail queue messages;
- automatically ban or unban IP addresses.

The only write-capable workflow is the explicit interactive Fail2ban menu. Every action requires confirmation, and the script protects the current SSH client IP from accidental blocking.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for more detail.

## Requirements

Recommended runtime:

- Debian or Ubuntu;
- Bash 5 or newer;
- root privileges for complete audit coverage.

Optional tools improve coverage when available:

```text
openssl
dig
sqlite3
fail2ban-client
journalctl
ss
nft
iptables
postconf
postqueue
doveconf
```

Unavailable checks are skipped instead of stopping the audit.

## Project Structure

```text
.
├── mail-sec-audit.sh          # Main audit script
├── README.md                  # English documentation
├── README_RU.md               # Russian documentation
├── docs/                      # Detailed guides and project notes
├── examples/                  # Example environment snippets
├── tests/                     # Smoke tests
├── .github/                   # CI, issue templates, PR template
├── CONTRIBUTING.md            # Contribution guide
├── SECURITY.md                # Vulnerability reporting policy
├── CHANGELOG.md               # Release notes
└── LICENSE                    # MIT License
```

## Documentation

- [Usage guide](docs/USAGE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Development guide](docs/DEVELOPMENT.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Development

Run local checks before opening a pull request:

```bash
bash -n mail-sec-audit.sh
bash tests/smoke.sh
shellcheck mail-sec-audit.sh tests/*.sh
```

GitHub Actions runs the same baseline checks on pushes and pull requests.

## Roadmap

Planned companion tools:

- `mail-external-audit`: external relay, TLS, banner, DNS, RBL, and port checks from another host;
- `mail-audit-collector`: centralized collection, baseline comparison, JSON output, fleet reporting, and notifications.

## Important Notes

- Local configuration analysis does not replace an external open-relay test.
- Failed login counts do not always equal unique attacker counts.
- Fail2ban counters can include addresses that were already unbanned.
- Mail-flow analytics is currently most detailed for Postfix.
- Always verify an IP address before manually blocking it.

## License

This project is distributed under the [MIT License](LICENSE).

## Author

**Anton Babaskin**  
GitHub: [@Anton-Babaskin](https://github.com/Anton-Babaskin)

