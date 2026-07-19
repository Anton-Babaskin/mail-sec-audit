<p align="right">
  рџ‡¬рџ‡§ English В· <a href="./docs/README.ru.md">рџ‡·рџ‡є Р СѓСЃСЃРєРёР№</a>
</p>

<div align="center">

# рџ“Ў SMTP Egress Audit

### Find out who is opening outbound SMTP connections before your provider blocks TCP/25

<p>
  A safe, read-only Bash toolkit for investigating abnormal outbound SMTP traffic on Linux servers.<br>
  Correlate network connections, processes, Postfix delivery, authenticated mail users and system logins вЂ” without capturing message content.
</p>

<p>
  <a href="https://github.com/Anton-Babaskin/smtp-egress-audit/actions/workflows/ci.yml">
    <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Anton-Babaskin/smtp-egress-audit/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=CI">
  </a>
  <img alt="Version" src="https://img.shields.io/badge/version-1.1.0-1f6feb?style=for-the-badge">
  <a href="./LICENSE">
    <img alt="MIT License" src="https://img.shields.io/github/license/Anton-Babaskin/smtp-egress-audit?style=for-the-badge">
  </a>
  <a href="https://github.com/Anton-Babaskin/smtp-egress-audit/commits/main">
    <img alt="Last commit" src="https://img.shields.io/github/last-commit/Anton-Babaskin/smtp-egress-audit?style=for-the-badge">
  </a>
</p>

<p>
  <img alt="Bash" src="https://img.shields.io/badge/Bash-4.4%2B-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white">
  <img alt="Postfix" src="https://img.shields.io/badge/Postfix-Audit-336791?style=for-the-badge">
  <img alt="Mail-in-a-Box" src="https://img.shields.io/badge/Mail--in--a--Box-Compatible-1f6feb?style=for-the-badge">
  <img alt="Platform" src="https://img.shields.io/badge/Debian%20%7C%20Ubuntu-Supported-E95420?style=for-the-badge&logo=ubuntu&logoColor=white">
  <img alt="Read only" src="https://img.shields.io/badge/Safety-Read--only-2ea043?style=for-the-badge&logo=securityscorecard&logoColor=white">
</p>

<p>
  <a href="https://github.com/Anton-Babaskin/smtp-egress-audit/stargazers">
    <img alt="Stars" src="https://img.shields.io/github/stars/Anton-Babaskin/smtp-egress-audit?style=flat-square">
  </a>
  <a href="https://github.com/Anton-Babaskin/smtp-egress-audit/issues">
    <img alt="Issues" src="https://img.shields.io/github/issues/Anton-Babaskin/smtp-egress-audit?style=flat-square">
  </a>
  <a href="https://github.com/Anton-Babaskin/smtp-egress-audit/forks">
    <img alt="Forks" src="https://img.shields.io/github/forks/Anton-Babaskin/smtp-egress-audit?style=flat-square">
  </a>
</p>

</div>

---

## рџљЁ Why this project exists

A hosting provider reports an unusual number of outbound connections to SMTP port 25 and warns that the port may be blocked. The usual explanations range from normal Postfix delivery and retry storms to a compromised mailbox, vulnerable web application, container or unknown process.

`smtp-egress-audit` preserves the evidence needed to tell those cases apart:

| Question | Evidence collected |
| -------- | ------------------ |
| Is the server really opening outbound SMTP connections? | Outbound TCP SYN count and destination grouping |
| Which process is responsible? | Repeated `ss -Htanp` snapshots with process and PID |
| Where is it connecting? | Destination IP, port and optional PTR hostname |
| Is Postfix sending mail? | Queue IDs, relay endpoints and `status=sent/deferred/bounced` |
| Which mailbox authenticated? | Postfix `sasl_username`, SMTP client hostname and IP |
| Was the server account accessed? | SSH, sudo, su, IMAP, POP3 and SMTP authentication events |
| Is this an open-relay attempt or real delivery? | Rejected inbound `NOQUEUE` events separated from outbound `postfix/smtp` delivery |
| Could a scheduled task or container be responsible? | Cron, systemd timers, Docker/Podman, conntrack and MTA processes |

> [!IMPORTANT]
> The tool performs **audit and monitoring only**. It does not modify the firewall, Postfix, SSH or Fail2ban; it does not block IP addresses; and it never captures packet payloads, credentials, message bodies or `/etc/postfix/sasl_passwd`.

---

## вњЁ Features

| Feature | Description |
| ------- | ----------- |
| рџЋЇ Exact outbound SYN capture | Monitors TCP SYN packets whose destination port matches `SMTP_PORT` |
| рџ”Њ Process and PID attribution | Takes regular `ss -Htanp` snapshots and optionally uses `tcpconnect-bpfcc` |
| рџ“Љ Destination grouping | Counts connections and groups remote IP:port endpoints |
| рџ“¬ Postfix delivery analysis | Counts sent, deferred, bounced and queued messages; shows relay endpoints and recipient domains |
| рџ”ђ SMTP account attribution | Extracts authenticated users from `sasl_username` with client hostname/IP |
| рџ§‘вЂЌрџ’» SSH audit | Shows current sessions, login history, effective SSH port and security settings |
| рџ“Ґ IMAP/POP3 audit | Extracts successful and failed Dovecot authentication by user and IP |
| рџ›Ў Fail2ban visibility | Shows global status and the `sshd` jail when installed |
| рџ§­ System context | Captures routes, services, reboot history, MTA processes, cron, timers and containers |
| рџЊђ Optional PTR lookup | Resolves successful-login IPs with a short timeout; DNS failure never aborts the audit |
| рџ§ѕ Private reports | Every run gets a timestamped directory with mode `0700` and files with mode `0600` |
| рџ”’ Secret redaction | Hides Postfix password maps, URL credentials and sensitive configuration values |
| вљ™пёЏ systemd integration | Includes opt-in continuous monitoring and a periodic report timer |
| рџ§Є Tested parsers | Synthetic fixtures cover Postfix, SSH, Dovecot, queue counting, redaction and validation |

---

## рџљЂ Quick start

### Install globally

```bash
git clone https://github.com/Anton-Babaskin/smtp-egress-audit.git
cd smtp-egress-audit
sudo ./install.sh
```

Run the first full audit:

```bash
sudo smtp-egress-audit audit
```

Watch outbound TCP/25 for ten minutes:

```bash
sudo smtp-egress-audit watch 600
```

The report is saved below:

```text
/var/log/smtp-egress-audit/YYYYMMDDTHHMMSSZ-MODE-PID/
```

> [!NOTE]
> The installer does not install packages and does not start continuous monitoring automatically. Use `sudo ./install.sh --enable-monitor` only when you explicitly want a persistent service.

### Run directly from the repository

```bash
chmod +x bin/smtp-egress-audit
sudo ./bin/smtp-egress-audit audit
```

---

## рџ›  Commands

| Command | Purpose |
| ------- | ------- |
| `smtp-egress-audit audit` | Full one-time system, Postfix, network and authentication audit |
| `smtp-egress-audit report` | Historical report for the period selected by `SINCE` |
| `smtp-egress-audit watch [seconds]` | Bounded network observation; default 600 seconds |
| `smtp-egress-audit monitor` | Continuous observation until SIGTERM or Ctrl+C |
| `smtp-egress-audit --help` | Show usage and environment options |
| `smtp-egress-audit --version` | Show the installed version |

Common examples:

```bash
sudo smtp-egress-audit audit
sudo smtp-egress-audit watch 3600
sudo smtp-egress-audit monitor
sudo SINCE="7 days ago" smtp-egress-audit report
sudo SMTP_PORT=587 smtp-egress-audit watch 600
sudo SMTP_PORT=2525 smtp-egress-audit watch 600
```

---

## рџ”Ћ Investigation model

```text
Provider alert
  в”‚
  в–ј
Preserve current system state
  в”‚
  в”њв”Ђв”Ђ Network в”Ђв”Ђв”Ђв”Ђв”Ђв–є outbound SYN в”Ђв–є destination IP:port
  в”‚                                     в”‚
  в”‚                                     в””в”Ђв”Ђ process + PID
  в”‚
  в”њв”Ђв”Ђ Postfix в”Ђв”Ђв”Ђв”Ђв”Ђв–є queue ID в”Ђв”Ђв”Ђв”Ђв”Ђв–є relay в”Ђв–є delivery status
  в”‚                       в”‚
  в”‚                       в””в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв–є sasl_username + client IP
  в”‚
  в”њв”Ђв”Ђ Access в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв–є SSH / sudo / su / IMAP / POP3 / SMTP auth
  в”‚
  в””в”Ђв”Ђ Persistence в”Ђв–є cron / timers / containers / other MTA
                          в”‚
                          в–ј
                 Correlate by timestamp
```

One connection is not necessarily one email. Deferred deliveries, connection failures and retries can produce many TCP connections for a much smaller number of messages.

---

## рџЊђ Network monitoring

The monitor uses the following base BPF expression:

```text
tcp dst port PORT and (tcp[tcpflags] & tcp-syn != 0)
```

When supported, `tcpdump -Q out` enforces the outbound direction. If `-Q out` is unavailable, the tool adds validated local source addresses to the BPF filter instead of accepting an ambiguous capture.

At the same time, it records `ss -Htanp` snapshots to preserve process/PID evidence. If `tcpconnect-bpfcc` is installed, it is started as a supplemental attribution source.

> [!CAUTION]
> No PCAP is created. The tool never uses `tcpdump -A`, `-X`, `-XX` or payload output. Only connection metadata required for attribution is stored.

### Direct TCP/25 vs external relay

| Scenario | Port to monitor | Typical owner |
| -------- | :-------------: | ------------- |
| Direct delivery from Postfix to recipient MX | `25` | `postfix/smtp` |
| Implicit TLS SMTP relay | `465` | Postfix or application client |
| Authenticated Submission relay | `587` | Postfix or application client |
| Alternate external relay | `2525` | Postfix or application client |

An external relay on 587/2525 can be completely healthy while the provider warning concerns unexpected direct delivery on TCP/25. Observe every relevant port separately.

---

## рџ“¬ Understanding Postfix evidence

| Log evidence | Direction | Meaning | Proves outbound delivery? |
| ------------ | --------- | ------- | :-----------------------: |
| `NOQUEUE: reject` | Inbound | Client rejected before a message entered the queue | вќЊ |
| `Relay access denied` | Inbound | Unauthorized relay attempt rejected | вќЊ |
| `postfix/smtp ... status=sent` | Outbound | Remote next hop accepted the delivery | вњ… |
| `status=deferred` | Outbound | Temporary failure; Postfix will retry | вљ пёЏ Attempt only |
| `status=bounced` | Outbound | Permanent delivery failure | вљ пёЏ Attempt only |
| `sasl_username=user@example.com` | Inbound submission | Identifies the authenticated mail account | Account evidence |
| `relay=host[address]:port` | Outbound | Shows the actual next-hop SMTP server | Route evidence |

> [!IMPORTANT]
> A large number of `Relay access denied` lines usually describes Internet background noise that your server successfully rejected. Do not confuse it with `postfix/smtp ... status=sent`, which is real outbound delivery evidence.

Sensitive `postconf -n` parameters are replaced with `configured` or `[REDACTED]`. The password database itself is never read.

---

## рџ”ђ Login and authentication audit

### Linux and SSH

- current users through `who` and `w`;
- login history through `last` and `lastlog`;
- established connections on the **effective SSH port**, including non-default ports;
- `Port`, `PermitRootLogin` and `PasswordAuthentication` from `sshd -T`;
- successful login method, username, source IP and optional PTR;
- failed-login source IP ranking and recent failures;
- recent `sudo` and `su` events;
- Fail2ban status and the `sshd` jail.

### Mail access

- authenticated Postfix SMTP Submission users;
- SMTP client hostname and source IP;
- successful Dovecot IMAP/POP3 logins;
- grouping by username and source IP;
- top failed-authentication source IPs;
- recent SMTP and Dovecot authentication errors.

---

## рџ§° Full audit coverage

| Area | Collected information |
| ---- | --------------------- |
| Host | Hostname, FQDN, date, timezone, uptime and reboot history |
| Network | Addresses, routes, active SMTP sockets and conntrack entries |
| Services | Postfix, Dovecot, SSH, Fail2ban, Docker and Podman state |
| Postfix | Queue, delivery status, relay, recipient domains, SASL users and non-default config |
| Access | Current users, SSH history, sudo/su, SMTP, IMAP and POP3 authentication |
| Persistence | Root crontab, `/etc/cron.d`, systemd timers and containers |
| Processes | Postfix, Exim, Sendmail and socket-owning process/PID data |

Postfix and Dovecot logs are read from `journalctl` when it contains relevant events. On traditional Ubuntu/Debian and Mail-in-a-Box logging setups, the tool safely falls back to `/var/log/mail.log`, `/var/log/maillog`, `/var/log/auth.log` or `/var/log/secure`.

---

## рџЋ› Configuration

Environment variables can be supplied directly or stored in `/etc/default/smtp-egress-audit` for systemd.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `LOG_ROOT` | `/var/log/smtp-egress-audit` | Private root directory for reports |
| `SMTP_PORT` | `25` | Destination TCP port to audit |
| `SINCE` | `24 hours ago` | Historical journal period |
| `SAMPLE_INTERVAL` | `1` | Seconds between socket snapshots |
| `ACTIVE_THRESHOLD` | `10` | Warn above this number of active connections |
| `INTERFACE` | `auto` | Default-route interface, explicit interface or `any` |
| `RESOLVE_HOSTNAMES` | `1` | Enable (`1`) or disable (`0`) PTR lookups |

All values are validated before use. Invalid ports, durations, booleans, paths or interface names terminate with a clear error instead of reaching system commands.

---

## рџ“Ѓ Report layout

```text
/var/log/smtp-egress-audit/
в””в”Ђв”Ђ 20260719T202507Z-audit-101599/
    в”њв”Ђв”Ђ report.txt
    в”њв”Ђв”Ђ mail.log
    в”њв”Ђв”Ђ auth.log
    в”њв”Ђв”Ђ postqueue.txt
    в”њв”Ђв”Ђ ssh-success.txt
    в””в”Ђв”Ђ dovecot-success.txt
```

Monitoring runs may also contain:

```text
tcpdump-syn.log
tcpdump.stderr
ss-snapshots.log
tcpconnect-bpfcc.log
tcpconnect-bpfcc.stderr
```

All directories use mode `0700`; report files use mode `0600`. Treat reports as confidential because they contain operational metadata and account names.

---

## вљ™пёЏ systemd

### Daily historical report

```bash
sudo systemctl enable --now smtp-egress-audit-report.timer
systemctl list-timers smtp-egress-audit-report.timer
```

### Continuous monitoring

```bash
sudo systemctl enable --now smtp-egress-audit-monitor.service
sudo systemctl status smtp-egress-audit-monitor.service
```

Stop it safely:

```bash
sudo systemctl disable --now smtp-egress-audit-monitor.service
```

SIGINT and SIGTERM stop background `tcpdump`/BPF processes and produce the final summary.

---

## рџ“¦ Mail-in-a-Box workflow

Mail-in-a-Box uses Postfix and Dovecot, so the same evidence chain applies:

1. preserve the provider's exact timestamp, timezone and destination port;
2. run `sudo smtp-egress-audit audit` immediately;
3. monitor the reported port with `watch`;
4. correlate process/PID with Postfix queue IDs and delivery status;
5. compare `sasl_username` with SMTP client IP and Dovecot activity;
6. inspect unexpected SSH users, cron jobs, timers and processes;
7. preserve the report before changing credentials or configuration.

> [!WARNING]
> Do not edit Mail-in-a-Box generated Postfix configuration just to investigate an alert. This tool deliberately remains read-only. Apply confirmed remediation through the platform's supported workflow.

See the complete [provider alert runbook](./docs/provider-alert-runbook.md).

---

## рџ§­ Provider-alert runbook

1. Record the source server IP, destination port, count, timezone and exact interval from the provider.
2. Run a full audit before rebooting or restarting services.
3. Start a bounded watch on the reported destination port.
4. Compare provider counts with local SYN counts and retry/deferred activity.
5. Identify whether the owner is Postfix, a web application, container, another MTA or unknown binary.
6. Correlate queue IDs, `status=sent`, relay endpoints, recipient domains and authenticated accounts.
7. Separate rejected inbound relay probes from successful outbound delivery.
8. Review SSH, Dovecot, SMTP auth, sudo/su, cron, timers, containers and Fail2ban.
9. Preserve evidence, then follow your incident-response procedure for containment and credential rotation.

> [!NOTE]
> A reboot removes active sockets, processes and some counters. Historical logs and timestamped provider flow records remain essential after a restart.

---

## рџ“‹ Requirements

| Type | Commands |
| ---- | -------- |
| Core | Bash 4.4+, `awk`, `sed`, `grep`, `sort`, `ss`, `journalctl` |
| Postfix | `postqueue`, `postconf` |
| Network monitoring | `tcpdump` |
| Optional attribution | `tcpconnect-bpfcc`, `conntrack` |
| Authentication | `sshd`, `last`, `lastlog`, `fail2ban-client` |
| Optional context | Docker, Podman, `getent`, `timeout` |

Supported targets:

- Ubuntu 22.04 and 24.04;
- current Debian releases;
- Postfix-based mail systems;
- Mail-in-a-Box.

Missing optional commands are reported as `not installed` or `unavailable` and do not abort the audit. The installer never installs system packages automatically.

---

## рџ“¦ Repository structure

```text
smtp-egress-audit/
в”њв”Ђв”Ђ .github/workflows/ci.yml
в”њв”Ђв”Ђ bin/smtp-egress-audit
в”њв”Ђв”Ђ config/smtp-egress-audit.default
в”њв”Ђв”Ђ docs/
в”‚   в”њв”Ђв”Ђ README.ru.md
в”‚   в””в”Ђв”Ђ provider-alert-runbook.md
в”њв”Ђв”Ђ fixtures/
в”‚   в”њв”Ђв”Ђ auth.log
в”‚   в”њв”Ђв”Ђ dovecot.log
в”‚   в”њв”Ђв”Ђ postconf.txt
в”‚   в”њв”Ђв”Ђ postfix.log
в”‚   в””в”Ђв”Ђ postqueue.txt
в”њв”Ђв”Ђ logrotate/smtp-egress-audit
в”њв”Ђв”Ђ systemd/
в”‚   в”њв”Ђв”Ђ smtp-egress-audit-monitor.service
в”‚   в”њв”Ђв”Ђ smtp-egress-audit-report.service
в”‚   в””в”Ђв”Ђ smtp-egress-audit-report.timer
в”њв”Ђв”Ђ tests/run-tests.sh
в”њв”Ђв”Ђ install.sh
в”њв”Ђв”Ђ uninstall.sh
в”њв”Ђв”Ђ Makefile
в”њв”Ђв”Ђ CHANGELOG.md
в”њв”Ђв”Ђ CONTRIBUTING.md
в”њв”Ђв”Ђ SECURITY.md
в””в”Ђв”Ђ LICENSE
```

---

## рџ§Є Development and CI

Run every local check:

```bash
make check
```

Or run stages separately:

```bash
make syntax
make shellcheck
make test
```

The test suite uses synthetic logs and documentation-only addresses. It covers:

- Postfix sent/deferred/bounced parsing;
- SMTP SASL username, client IP and hostname extraction;
- non-default SSH port and login parsing;
- Dovecot username/IP extraction;
- Postfix queue counting;
- sensitive Postfix configuration redaction;
- argument and environment validation;
- exact tcpdump BPF construction;
- missing optional utility behavior.

GitHub Actions runs Bash syntax checks, ShellCheck, the complete test suite and Gitleaks secret scanning.

---

## рџ›џ Troubleshooting

| Symptom | Resolution |
| ------- | ---------- |
| `Permission denied` while creating reports | Run with `sudo` or choose a writable absolute `LOG_ROOT`. |
| `tcpdump: not installed` | Install it through your normal package-management process, then rerun `watch`. |
| `0` outbound SYN | No matching SYN was observed during the window, or capture permissions/tooling were unavailable; inspect diagnostics. |
| No Postfix events in journald | The tool automatically falls back to traditional mail logs when relevant journal records are absent. |
| SSH sessions missing on a custom port | Version 1.1.0 detects the effective port through `sshd -T`; verify `sshd -T | grep '^port '`. |
| Queue count differs from provider connections | Connections, messages and recipients are different metrics; retries can create multiple connections. |
| PTR lookup fails | DNS failure is non-fatal; set `RESOLVE_HOSTNAMES=0` to disable lookups. |

---

## вљ пёЏ Limitations

- Reboots destroy volatile socket/process evidence.
- Log rotation and journald retention can remove older events.
- File-log fallback cannot perfectly reproduce arbitrary `journalctl --since` filtering.
- NAT, namespaces and extremely short-lived connections may limit attribution.
- PTR records are hints, not proof of identity.
- This is an evidence-collection tool, not malware detection or a replacement for incident response.

---

## рџ—‘ Uninstall

```bash
sudo ./uninstall.sh
```

Accumulated reports are preserved by default. Remove them only with the explicit destructive option:

```bash
sudo ./uninstall.sh --purge-logs
```

---

## рџ¤ќ Contributing

Contributions are welcome. Before opening a pull request:

```bash
make check
```

Please read:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CHANGELOG.md](./CHANGELOG.md)

Never include production IP addresses, domains, usernames, mail logs, credentials or private infrastructure details in issues, fixtures or pull requests.

---

## вљ–пёЏ License

Distributed under the [MIT License](./LICENSE).

Copyright В© 2026 Anton Babaskin.

---

## в„№пёЏ Disclaimer

This is an independent community project and is not affiliated with or officially supported by Postfix, Mail-in-a-Box or any hosting provider.

Always review collected evidence and test the tool in your own environment before relying on it during an incident.
