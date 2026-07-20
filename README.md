# Mail Security Audit

`mail-sec-audit` is a read-only Bash audit for Linux mail servers. It provides a structured view of service health, network exposure, authentication activity, mail flow, DNS, TLS, firewall policy and host security without silently changing production configuration.

Version: **2.2.3**

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

## Quick start

```bash
git clone https://github.com/Anton-Babaskin/mail-sec-audit.git
cd mail-sec-audit
chmod +x mail-sec-audit.sh
sudo ./mail-sec-audit.sh
```

Audit a defined period and mail identity:

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector mail
```

Run additional checks and save a private report:

```bash
sudo ./mail-sec-audit.sh --deep --report /root/mail-audit.txt
```

Allow documented non-mail public ports during exposure evaluation:

```bash
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" ./mail-sec-audit.sh
```

Show all options:

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
