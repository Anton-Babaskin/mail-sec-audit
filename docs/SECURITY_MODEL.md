# Security Model

Mail Security Audit is intended to inspect local server state and report
findings without changing production configuration.

## Default behavior

By default, the script must not:

- change firewall rules;
- restart services;
- install or remove packages;
- modify SSH, Postfix, Exim, Dovecot, or DNS configuration;
- delete mail queue messages;
- ban or unban IP addresses.

## Interactive mode

Interactive Fail2ban actions are opt-in and require explicit confirmation.
The script should protect the current SSH client IP from accidental blocking.

## Sensitive output

Audit output can include:

- server hostnames and domains;
- public and private IP addresses;
- service names and open ports;
- authentication failure metadata;
- mail queue and log statistics.

Generated reports should be treated as sensitive operational documents.

