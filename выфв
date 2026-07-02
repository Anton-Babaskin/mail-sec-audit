# 🛡️ Mail Security Audit

<p align="center">
  <strong>Universal security audit script for Linux mail servers</strong>
</p>

<p align="center">
  Postfix • Exim • Dovecot • Fail2ban • UFW • nftables • TLS • DNS • Mail Logs
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Bash-5%2B-4EAA25?logo=gnubash&logoColor=white" alt="Bash">
  <img src="https://img.shields.io/badge/Linux-Debian%20%7C%20Ubuntu-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Mode-Read--only%20by%20default-2ea44f" alt="Read-only">
  <img src="https://img.shields.io/badge/Status-Active-blue" alt="Status">
</p>

---

## 📖 Overview

**Mail Security Audit** is a universal Bash script for auditing the security and operational state of Linux mail servers.

It automatically detects the installed mail stack, analyzes system security, checks exposed services, reviews authentication failures, validates TLS and DNS settings, inspects mail queues, and displays the results in a clear colorized interface.

The script is designed for quick manual audits, recurring maintenance, and troubleshooting of production mail servers.

> 🟢 The audit is read-only by default.  
> 🔴 No firewall rules or mail server settings are modified automatically.

---

## ✨ Features

### 🖥️ System and updates

- Operating system and kernel information
- Pending package updates
- Automatic security update status
- Reboot-required detection
- Failed systemd services
- Disk space and inode usage

### 🔐 SSH security

- Effective `sshd` configuration
- Root login status
- Password authentication status
- Public key authentication
- Maximum authentication attempts
- Successful SSH logins
- Failed SSH authentication attempts
- Top attacking IP addresses
- Recent login history
- Suspicious UID `0` accounts
- SSH authorized key inspection

### 🌐 Network and firewall

- Listening TCP and UDP ports
- Publicly exposed services
- Unexpected port detection
- UFW status and active rules
- nftables and iptables detection
- INPUT, OUTPUT and FORWARD policies
- Fail2ban firewall chains
- Dangerous database ports exposed publicly

### 🚫 Brute-force protection

- Fail2ban service status
- Active jail detection
- Current and total banned IP statistics
- CrowdSec detection
- sshguard detection
- Interactive IP ban and unban menu
- Protection against banning the current SSH client IP
- Manual confirmation before every ban operation

### 📧 Mail server detection

Supported and automatically detected components:

- Postfix
- Exim
- Sendmail
- OpenSMTPD
- Dovecot
- Courier

### 📊 Mail authentication analysis

- Dovecot authentication failures
- Postfix SASL authentication failures
- Top attacking IP addresses
- Authentication statistics for a selected period
- IPv4 and IPv6 extraction
- Successful and failed mail authentication events

### 📬 Mail flow analytics

For Postfix servers:

- Top incoming sender domains
- Top outgoing recipient domains
- Successful delivery statistics
- Unique sender domain count
- Unique recipient domain count
- Queue ID correlation between Postfix log events
- Configurable top-domain limit

### 📦 Mail queue analysis

- Current queue size
- Postfix queue inspection
- Exim queue inspection
- Deferred message detection
- Warning thresholds for large queues

### 🔁 Relay security

- Postfix relay restriction analysis
- `mynetworks` inspection
- `reject_unauth_destination` validation
- Exim relay configuration detection
- Warning when a real external relay test is required

### 🔒 TLS and certificates

- Local TLS service detection
- HTTPS certificate inspection
- SMTP STARTTLS checks
- IMAP STARTTLS checks
- POP3 STARTTLS checks
- Certificate subject and issuer
- Certificate expiration date
- Hostname validation
- Remaining certificate lifetime
- Legacy TLS protocol detection in deep mode

### 🌍 DNS and email authentication

- MX record checks
- SPF record detection
- DMARC policy detection
- DKIM selector lookup
- PTR reverse DNS inspection
- Mail hostname validation

### 🧩 System integrity

- SUID binary detection
- SGID checks in deep mode
- World-writable file detection
- Package integrity checks
- Recently modified system files
- Cron job inspection
- systemd timer inspection
- Backup tool and job detection

---

## 🚀 Quick start

### 1. Create the script

```bash
nano mail-sec-audit.sh

Paste the script and save:

Ctrl+O
Enter
Ctrl+X
2. Set permissions
chmod 700 mail-sec-audit.sh
3. Run the audit
sudo ./mail-sec-audit.sh
⚙️ Usage examples
Basic audit
sudo ./mail-sec-audit.sh
Audit the last 7 days
sudo ./mail-sec-audit.sh \
  --days 7
Audit a specific mail server
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com
Extended output
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --verbose
Interactive Fail2ban menu
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --interactive
Display top 100 mail domains
sudo ./mail-sec-audit.sh \
  --days 30 \
  --hostname mail.example.com \
  --domain example.com \
  --mail-top 100
Check a DKIM selector
sudo ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector mail
Save the audit report
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --report /root/mail-audit-$(date +%F).log
Deep audit
sudo ./mail-sec-audit.sh \
  --deep \
  --days 30 \
  --hostname mail.example.com \
  --domain example.com
🎛️ Main options
Option	Description
--days N	Analyze logs for the last N days
--hostname HOST	Mail server hostname
--domain DOMAIN	Primary email domain
--dkim-selector NAME	DKIM selector to check
--mail-top N	Number of incoming and outgoing domains to display
--verbose	Show extended diagnostic information
--interactive	Open the interactive Fail2ban management menu
--deep	Run slower and more detailed checks
--report FILE	Save the audit output to a file
--no-color	Disable terminal colors
--help	Display usage information
🎨 Status indicators

The script uses clear visual status levels:

[  OK  ] Check passed
[ INFO ] Informational result
[ WARN ] Review recommended
[ FAIL ] Critical security or configuration issue

Example:

[  OK  ] Firewall backend: UFW
[  OK  ] INPUT policy: DROP
[  OK  ] Fail2ban service is active
[ WARN ] PasswordAuthentication is enabled
[ FAIL ] Firewall is inactive
🚫 Interactive IP management

The interactive mode allows you to safely manage Fail2ban bans.

sudo ./mail-sec-audit.sh --interactive

Available actions:

1) Ban an IP address in a selected Fail2ban jail
2) Unban an IP address from all Fail2ban jails
3) Display currently banned IP addresses
0) Exit without changes

Before blocking an address, the script validates that it is not:

the current SSH client IP;
a local server IP;
a loopback address;
a private network address;
a link-local address;
a multicast address.

Every ban requires explicit confirmation.

🔌 Allowed custom ports

To allow expected non-standard services such as Zabbix Agent or Node Exporter:

sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" \
  ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com

Without this variable, these ports will be displayed as unexpected listeners.

📤 Exit codes
Code	Meaning
0	Audit completed without warnings
1	One or more warnings found
2	One or more critical issues found

Example:

sudo ./mail-sec-audit.sh
echo $?

This makes the script suitable for:

cron jobs;
systemd timers;
Ansible;
monitoring systems;
CI pipelines;
centralized audit collectors.
🧰 Requirements

Recommended environment:

Debian
Ubuntu
Bash 5+
Root privileges

Optional utilities improve audit coverage:

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

The script skips unavailable checks instead of terminating.

🛡️ Safety model

The normal audit mode does not:

modify firewall rules;
restart services;
install packages;
change SSH configuration;
change Postfix or Dovecot configuration;
delete mail queue messages;
automatically block IP addresses.

The only write operation is manual IP management through the interactive Fail2ban menu.

🧪 Recommended workflow
1. Run the audit
2. Review WARN and FAIL results
3. Verify successful SSH login IP addresses
4. Inspect unexpected listening ports
5. Review mail authentication failures
6. Check mail queue growth
7. Verify TLS certificate expiration
8. Validate MX, SPF, DMARC and DKIM
9. Run deep mode periodically
10. Save reports for future comparison
🗺️ Project roadmap

Planned companion tools:

🌐 mail-external-audit

External mail server testing from another VPS:

real open-relay testing;
external SMTP and IMAP TLS checks;
certificate chain validation;
SMTP banner analysis;
PTR and forward-confirmed reverse DNS;
RBL blacklist checks;
external port availability;
authentication exposure detection.
📡 mail-audit-collector

Centralized audit collection:

collect results from multiple servers;
compare server baselines;
detect new ports and SSH keys;
identify firewall changes;
create centralized reports;
Telegram notifications;
JSON output;
fleet-wide security summaries.
⚠️ Important notes
Local configuration analysis cannot fully replace an external open-relay test.
A high number of failed login events does not always mean the same number of unique attackers.
Fail2ban counters may include addresses that were already unbanned.
Mail flow analytics currently provides the most detailed results on Postfix servers.
Always verify an IP address before manually blocking it.
🤝 Contributing

Bug reports, improvements, additional mail server support, and pull requests are welcome.

Suggested contribution areas:

Exim mail flow analytics
Sendmail log parsing
JSON output
HTML reports
Telegram notifications
Baseline comparison
External SMTP testing
Additional Linux distributions
📄 License

This project is distributed under the MIT License.

👤 Author

Anton Babaskin

GitHub: @Anton-Babaskin
