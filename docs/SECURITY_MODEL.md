# Security Model

Mail Security Audit inspects a mail server and reports findings without
changing it. This document states what it does, what it never does, and the
limits of its guarantees.

## Read-only by construction

All external commands go through `mail_sec_audit/runner.py`:

- each allowed command is a table entry with the program, the exact argument
  shape, a timeout, an output limit and the reason it has no side effects;
- commands run as an argv list without a shell, with a fixed `PATH`,
  `LC_ALL=C`, stdin from `/dev/null` and their own process group;
- `mailinabox` (a wrapper around `setup/start.sh`) and Mailcow `update.sh` are
  refused with any arguments, also inside containers;
- `docker` is limited to `ps`, `inspect` with fixed templates, `logs` and
  `exec` without options; the inner command must match an entry marked safe for
  containers;
- entries that change state (`fail2ban-client set … banip/unbanip`,
  `fail2ban-client unban`, `logger`) run only inside the interactive menu after
  confirmation.

Known side effects of allowed reads, kept on purpose:

- `nft list ruleset` may load the `nf_tables` module if it is not loaded; no
  rules or policies change. Legacy `iptables -S` runs only when
  `/proc/net/ip_tables_names` shows the tables are already loaded;
- TLS probes and `postqueue`/`postconf` calls produce normal log lines;
- `dnf check-update` is run with `--setopt=logdir=` pointing to the private
  temporary directory.

Static tests fail the build if `subprocess`, `shell=`, `eval` or `exec` appear
outside the runner, or if the source mentions secret files.

## Secrets

Never read: password hashes (`/etc/shadow`; empty passwords come from
`passwd -S`), private keys, `sasl_passwd`, `mailcow.conf`, message bodies or
queue files. `doveconf` is called only with an explicit list of settings and
never with `-x` (which would print key contents).

## Network

- TLS probes connect only to local listener addresses (127.0.0.1/::1 for
  wildcard binds). Certificate verification is off on purpose: expired or
  self-signed certificates must be read to be reported.
- DNS queries are sent only when `--domain` is given.
- Both lists appear in every report (`Local probes`, `External queries`).

## Untrusted input

Values from logs, DNS, certificates and command output are data. The
terminal renderer escapes control characters, ANSI sequences and bidi
overrides; JSON escapes them by definition. Log timestamps are accepted only at
the start of a line, and Postfix fields are parsed in their fixed order, so
hostile addresses or remote responses cannot change counters. Recommendations
are static catalog texts and contain no destructive commands (tested).

## Files, lock and signals

- Reports: `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, written through the same
  descriptor. Appending requires a regular file owned by the effective user,
  with one link and no group/other write permission.
- A missing parent directory is created with mode 0700.
- Temporary files live in a private `mkdtemp` directory removed on exit.
- One audit at a time: `flock` on `/run/mail-sec-audit.lock` (root) or in
  `XDG_RUNTIME_DIR`; a second run exits with 75.
- `INT`, `TERM` and `HUP` stop the audit: running children are killed, an
  unfinished new report is removed, the temporary directory is cleaned and the
  exit code is 128+N.
- The wrapper runs Python with `-I`, so modules in the working directory and
  `PYTHON*` variables are ignored.

## Interactive mode

`--interactive` is the only workflow that changes the system. It requires a
terminal and root, shows each command, and needs `BAN` or `UNBAN` typed.
It refuses invalid and non-global addresses, the host's own addresses and the
peer address of every established SSH connection to the SSH ports (not only
`SSH_CONNECTION`, which `sudo` removes by default). This reduces operator error
but does not replace console access and a second administrative session.

## Honest results

No data, no permission, a missing tool, a timeout or truncated output gives
`UNKNOWN` with a reason; such findings set exit code 1. Checks that do not
apply give `N/A`. A crash inside one check becomes `UNKNOWN`
(`internal_error`) and the rest of the report is produced.

## Trust assumptions and limits

A compromised host can lie to a local auditor: the kernel, utilities, Docker
daemon and log files are assumed honest. A local audit cannot prove the absence
of an open relay or validate TLS as seen from the Internet; those need an
external probe. Statistics depend on log retention and format; queue IDs may
repeat across very long periods when `enable_long_queue_ids` is off.
