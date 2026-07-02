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

> 🟢 The audit is read-only by default.  
> 🔴 Firewall rules and mail server settings are not modified automatically.

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
- Root login and password authentication status
- Public-key authentication status
- Successful and failed SSH logins
- Top attacking IP addresses
- Recent login history
- Suspicious UID `0` accounts
- SSH authorized-key inspection

### 🌐 Network and firewall

- Listening TCP and UDP ports
- Publicly exposed services
- Unexpected port detection
- UFW, nftables and iptables detection
- INPUT, OUTPUT and FORWARD policies
- Fail2ban firewall chains
- Detection of dangerous database ports exposed publicly

### 🚫 Brute-force protection

- Fail2ban service and jail status
- Current and total banned IP statistics
- CrowdSec and sshguard detection
- Interactive IP ban and unban menu
- Protection against banning the current SSH client IP
- Explicit confirmation before every ban operation

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
- Top attacking IPv4 and IPv6 addresses
- Authentication statistics for a selected period

### 📬 Mail flow analytics

For Postfix servers:

- Top incoming sender domains
- Top outgoing recipient domains
- Successful delivery statistics
- Unique sender and recipient domain counts
- Queue-ID correlation between Postfix log events
- Configurable top-domain limit

### 📦 Mail queue analysis

- Current Postfix or Exim queue size
- Deferred message detection
- Warning thresholds for large queues

### 🔁 Relay security

- Postfix relay restriction analysis
- `mynetworks` inspection
- `reject_unauth_destination` validation
- Exim relay configuration detection
- Reminder that a real open-relay test must be performed externally

### 🔒 TLS and certificates

- HTTPS certificate inspection
- SMTP, IMAP and POP3 STARTTLS checks
- Certificate subject, issuer and expiration
- Hostname validation
- Remaining certificate lifetime
- Legacy TLS protocol detection in deep mode

### 🌍 DNS and email authentication

- MX record checks
- SPF record detection
- DMARC policy detection
- DKIM selector lookup
- PTR reverse-DNS inspection
- Mail-hostname validation

### 🧩 System integrity

- SUID binary detection
- SGID checks in deep mode
- World-writable file detection
- Package-integrity checks
- Recently modified system files
- Cron and systemd timer inspection
- Backup tool and job detection

---

## 🚀 Quick start

### 1. Create the script

```bash
nano mail-sec-audit.sh
```

Paste the script and save it:

```text
Ctrl+O
Enter
Ctrl+X
```

### 2. Set permissions

```bash
chmod 700 mail-sec-audit.sh
```

### 3. Run the audit

```bash
sudo ./mail-sec-audit.sh
```

---

## ⚙️ Usage examples

### Basic audit

```bash
sudo ./mail-sec-audit.sh
```

### Audit the last 7 days

```bash
sudo ./mail-sec-audit.sh --days 7
```

### Audit a specific mail server

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com
```

### Extended output

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --verbose
```

### Interactive Fail2ban menu

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --interactive
```

### Display top 100 mail domains

```bash
sudo ./mail-sec-audit.sh \
  --days 30 \
  --hostname mail.example.com \
  --domain example.com \
  --mail-top 100
```

### Check a DKIM selector

```bash
sudo ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector mail
```

### Save an audit report

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --report /root/mail-audit-$(date +%F).log
```

### Deep audit

```bash
sudo ./mail-sec-audit.sh \
  --deep \
  --days 30 \
  --hostname mail.example.com \
  --domain example.com
```

---

## 🎛️ Main options

| Option | Description |
|---|---|
| `--days N` | Analyze logs for the last `N` days |
| `--hostname HOST` | Mail server hostname |
| `--domain DOMAIN` | Primary email domain |
| `--dkim-selector NAME` | DKIM selector to check |
| `--mail-top N` | Number of incoming and outgoing domains to display |
| `--verbose` | Show extended diagnostic information |
| `--interactive` | Open the interactive Fail2ban menu |
| `--deep` | Run slower and more detailed checks |
| `--report FILE` | Save the audit output to a file |
| `--no-color` | Disable terminal colors |
| `--help` | Display usage information |

---

## 🎨 Status indicators

```text
[  OK  ] Check passed
[ INFO ] Informational result
[ WARN ] Review recommended
[ FAIL ] Critical security or configuration issue
```

---

## 🚫 Interactive IP management

Run:

```bash
sudo ./mail-sec-audit.sh --interactive
```

Available actions:

```text
1) Ban an IP address in a selected Fail2ban jail
2) Unban an IP address from all Fail2ban jails
3) Display currently banned IP addresses
0) Exit without changes
```

Before blocking an address, the script checks that it is not:

- the current SSH client IP;
- a local server IP;
- a loopback address;
- a private network address;
- a link-local address;
- a multicast address.

Every ban requires explicit confirmation.

---

## 🔌 Allowed custom ports

To allow expected non-standard services such as Zabbix Agent or Node Exporter:

```bash
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" \
  ./mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com
```

---

## 📤 Exit codes

| Code | Meaning |
|---:|---|
| `0` | Audit completed without warnings |
| `1` | One or more warnings found |
| `2` | One or more critical issues found |

This makes the script suitable for cron jobs, systemd timers, Ansible, monitoring systems, CI pipelines and centralized audit collectors.

---

## 🧰 Requirements

Recommended environment:

- Debian
- Ubuntu
- Bash 5+
- Root privileges

Optional utilities improve audit coverage:

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

Unavailable checks are skipped without terminating the audit.

---

## 🛡️ Safety model

Normal audit mode does not:

- modify firewall rules;
- restart services;
- install packages;
- change SSH configuration;
- change Postfix or Dovecot configuration;
- delete mail queue messages;
- automatically block IP addresses.

The only write operation is manual IP management through the interactive Fail2ban menu.

---

## 🗺️ Project roadmap

### 🌐 `mail-external-audit`

External mail-server testing from another VPS:

- real open-relay testing;
- external SMTP and IMAP TLS checks;
- certificate-chain validation;
- SMTP banner analysis;
- PTR and forward-confirmed reverse DNS;
- RBL blacklist checks;
- external port availability;
- authentication exposure detection.

### 📡 `mail-audit-collector`

Centralized audit collection:

- collect results from multiple servers;
- compare server baselines;
- detect new ports and SSH keys;
- identify firewall changes;
- create centralized reports;
- send Telegram notifications;
- provide JSON output;
- produce fleet-wide security summaries.

---

## ⚠️ Important notes

- Local configuration analysis cannot replace an external open-relay test.
- A high number of failed login events does not necessarily mean the same number of unique attackers.
- Fail2ban counters may include addresses that were already unbanned.
- Mail-flow analytics is currently most detailed on Postfix servers.
- Always verify an IP address before manually blocking it.

---

## 🤝 Contributing

Bug reports, improvements, support for additional mail servers and pull requests are welcome.

Useful contribution areas:

- Exim mail-flow analytics
- Sendmail log parsing
- JSON output
- HTML reports
- Telegram notifications
- Baseline comparison
- External SMTP testing
- Additional Linux distributions

---

## 📄 License

This project is distributed under the MIT License.

---

## 👤 Author

**Anton Babaskin**

GitHub: [@Anton-Babaskin](https://github.com/Anton-Babaskin)

---

<p align="center">
  <strong>Built for practical Linux mail-server security auditing.</strong>
</p>

<p align="center">
  🛡️ Secure • 📊 Analyze • 🔍 Detect • 🚫 Protect
</p>

---

# 🇷🇺 Русское описание

## 📖 О проекте

**Mail Security Audit** — универсальный Bash-скрипт для проверки безопасности и рабочего состояния почтовых серверов Linux.

Он автоматически определяет установленный почтовый стек, анализирует безопасность системы, проверяет доступные снаружи сервисы, изучает ошибки авторизации, проверяет TLS и DNS, анализирует почтовую очередь и отображает результаты в удобном цветном интерфейсе.

> 🟢 По умолчанию аудит работает только в режиме чтения.  
> 🔴 Скрипт автоматически не изменяет firewall и конфигурацию почтового сервера.

## 🚀 Быстрый запуск

```bash
chmod 700 mail-sec-audit.sh
sudo ./mail-sec-audit.sh
```

Проверка конкретного сервера:

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --verbose
```

Интерактивное меню Fail2ban:

```bash
sudo ./mail-sec-audit.sh \
  --days 7 \
  --hostname mail.example.com \
  --domain example.com \
  --interactive
```

## 🎛️ Основные параметры

| Параметр | Описание |
|---|---|
| `--days N` | Анализировать логи за последние `N` дней |
| `--hostname HOST` | Hostname почтового сервера |
| `--domain DOMAIN` | Основной почтовый домен |
| `--dkim-selector NAME` | DKIM selector для проверки |
| `--mail-top N` | Количество входящих и исходящих доменов |
| `--verbose` | Расширенный диагностический вывод |
| `--interactive` | Интерактивное меню Fail2ban |
| `--deep` | Более глубокие и медленные проверки |
| `--report FILE` | Сохранить отчёт в файл |
| `--no-color` | Отключить цветной вывод |
| `--help` | Показать справку |

## 🎨 Статусы проверки

```text
[  OK  ] Проверка успешно пройдена
[ INFO ] Информационный результат
[ WARN ] Рекомендуется проверить
[ FAIL ] Критическая проблема безопасности или конфигурации
```

## 🛡️ Модель безопасности

В обычном режиме скрипт не выполняет:

- изменение firewall;
- перезапуск сервисов;
- установку пакетов;
- изменение SSH;
- изменение Postfix или Dovecot;
- удаление писем из очереди;
- автоматическую блокировку IP.

Единственная операция записи — ручное управление Fail2ban через интерактивное меню.

## 🗺️ План развития

Планируются два дополнительных инструмента:

- `mail-external-audit` — внешний SMTP, TLS, DNS, RBL и open-relay аудит;
- `mail-audit-collector` — централизованный сбор отчётов, baseline, JSON и Telegram-уведомления.

## 👤 Автор

**Anton Babaskin**

GitHub: [@Anton-Babaskin](https://github.com/Anton-Babaskin)
