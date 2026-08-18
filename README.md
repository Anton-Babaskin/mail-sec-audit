<div align="center">

# 🛡️ Mail Security Audit

### Read-only security posture for production Linux mail servers

<img src="https://img.shields.io/badge/version-2.2.3-2563eb?style=for-the-badge" alt="Version 2.2.3">
<img src="https://img.shields.io/badge/Bash-4%2B-121011?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash 4+">
<img src="https://img.shields.io/badge/default-read--only-16a34a?style=for-the-badge" alt="Read-only by default">
<img src="https://img.shields.io/github/license/Anton-Babaskin/mail-sec-audit?style=for-the-badge&color=0ea5e9" alt="License">

<a href="#-quick-start">Quick Start</a> · <a href="#what-it-checks">Checks</a> · <a href="#safety-model">Safety</a> · <a href="#-usage-examples">Usage</a>

</div>

---

## ⚡ Quick Start

```bash
git clone https://github.com/Anton-Babaskin/mail-sec-audit.git
cd mail-sec-audit
chmod +x mail-sec-audit.sh
sudo ./mail-sec-audit.sh
```

> [!NOTE]
> The default path is read-only. Exit codes distinguish a clean result, warnings, and critical findings.

**Best for:** incident triage, maintenance reviews and security baselining across Postfix, Exim, Sendmail and OpenSMTPD hosts.

## Scope

The script supports common combinations of:

- Postfix, Exim, Sendmail and OpenSMTPD
- Dovecot and Courier
- systemd and journald
- UFW, firewalld, nftables and iptables
- Fail2Ban

It is designed for incident triage, maintenance reviews and security baselining on Debian/Ubuntu-style mail servers, including Mail-in-a-Box deployments.

## What it checks

- Host identity, uptime, resources and listening services
- MTA and IMAP/POP service state
- Mail queue and recent delivery/authentication activity
- SSH exposure, sessions and recent login events
- Firewall rules and unexpected public ports
- Fail2Ban service and jail state
- TLS certificates and expiration
- MX, SPF, DMARC and optional DKIM DNS records
- Selected mail-server hardening signals
- Findings summarized as `OK`, `WARN` and `FAIL`

## Safety model

The default audit path is read-only. It does not automatically rewrite Postfix, firewall, SSH or Fail2Ban configuration.

The optional interactive mode can expose explicitly confirmed maintenance actions. Review every prompt before approving a change on a production server.

Reports are created with restrictive permissions, and temporary files are removed on exit.

## Requirements

- Linux with Bash
- Root privileges for complete logs, service state and firewall visibility
- Standard GNU userland
- Optional tools such as `dig`, `openssl`, `fail2ban-client` and the active firewall frontend improve coverage

Missing optional tools are reported; they should not make the complete audit fail unexpectedly.

## 🧭 Usage examples

Audit a defined period and mail identity:

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector mail
```

Run deeper checks and save a private report:

```bash
sudo ./mail-sec-audit.sh --deep --report /root/mail-audit.txt
```

Allow documented non-mail public ports during exposure evaluation:

```bash
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" ./mail-sec-audit.sh
```

Show every option:

```bash
./mail-sec-audit.sh --help
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | No warnings or critical findings |
| `1` | One or more warnings |
| `2` | One or more critical findings |

This makes the tool suitable for manual review and controlled automation. Always review the report details before treating an exit code as a complete security decision.

## Related projects

- [smtp-egress-audit](https://github.com/Anton-Babaskin/smtp-egress-audit) is the focused tool for attributing abnormal outbound SMTP/TCP connections.
- [miab-radar](https://github.com/Anton-Babaskin/miab-radar) provides operational health and deliverability diagnostics specifically for Mail-in-a-Box.
- [mail_analyzer.sh](https://github.com/Anton-Babaskin/mail_analyzer.sh) provides deeper Postfix log statistics.

These projects are complementary: this repository owns broad mail-server security posture, not packet-level SMTP egress attribution or general log analytics.

## License

See [LICENSE](./LICENSE).
