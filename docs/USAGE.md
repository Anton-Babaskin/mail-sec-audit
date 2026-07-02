# Usage Guide

## Basic run

```bash
sudo bash mail-sec-audit.sh
```

## Analyze a specific period

```bash
sudo bash mail-sec-audit.sh --days 14
```

## Enable DNS and TLS checks for a mail domain

```bash
sudo bash mail-sec-audit.sh \
  --hostname mail.example.com \
  --domain example.com \
  --dkim-selector default
```

## Save a report

```bash
sudo bash mail-sec-audit.sh --report ./reports/audit.txt
```

Reports can contain operationally sensitive data. Keep them out of git and
share them only with trusted recipients.

## Allow known public monitoring ports

```bash
sudo MAIL_AUDIT_ALLOWED_PORTS="10050 9100" bash mail-sec-audit.sh
```

