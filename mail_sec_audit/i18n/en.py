"""English catalog. Keys and placeholders must match ``ru.py``."""

from __future__ import annotations

MESSAGES: dict[str, str] = {
    # --- command line ---------------------------------------------------------
    "cli.usage": (
        "Usage:\n"
        "  sudo bash mail-sec-audit.sh [options]\n"
        "\n"
        "Options:\n"
        "  --days N              Log analysis period in days, default 7\n"
        "  --mail-top N          Rows in mail statistics tables, default 20\n"
        "  --from YYYY-MM-DD     First day of the period, inclusive\n"
        "  --to YYYY-MM-DD       Last day of the period, inclusive\n"
        "  --hostname FQDN       Mail server name for TLS checks\n"
        "  --domain DOMAIN       Mail domain for MX/SPF/DMARC checks (enables DNS queries)\n"
        "  --dkim-selector SEL   DKIM selector for the DNS check\n"
        "  --platform NAME       auto, generic, mailcow, iredmail or mailinabox\n"
        "  --format FORMAT       text, json or fleetops\n"
        "  --lang LANG           ru or en; default from LC_ALL, LC_MESSAGES, LANG\n"
        "  --redact              Hide e-mail addresses, IP addresses, host and user names\n"
        "  --deep                Slower checks: legacy TLS, package integrity, full SUID scan\n"
        "  --report FILE         Write the report to a new file with mode 0600\n"
        "  --append-report FILE  Append a text report to an existing private file\n"
        "  --interactive         After the audit, open the Fail2ban menu (changes need confirmation)\n"
        "  --verbose             Show evidence for every finding\n"
        "  --no-color            Disable ANSI colors\n"
        "  --version             Print the version and exit\n"
        "  -h, --help            Print this help\n"
        "\n"
        "Additional allowed public ports:\n"
        '  MAIL_AUDIT_ALLOWED_PORTS="10050 9100" sudo bash mail-sec-audit.sh\n'
        "\n"
        "The audit is read-only. Changes are possible only in --interactive mode and only\n"
        "after confirming each operation.\n"
        "\n"
        "Exit codes: 0 clean, 1 WARN or UNKNOWN, 2 FAIL, 64 usage error, 69 no suitable\n"
        "Python, 73 report file error, 75 another audit is running, 128+N stopped by signal N."
    ),
    "cli.error.prefix": "Error: {message}",
    "cli.error.requires_value": "{option} requires a value",
    "cli.error.days": "--days requires a number from 1 to 3650",
    "cli.error.mail_top": "--mail-top requires a number from 1 to 100",
    "cli.error.date": "{option} requires a valid date YYYY-MM-DD",
    "cli.error.dns_name": "{option} contains an invalid name: {value}",
    "cli.error.platform": "unknown platform: {value}",
    "cli.error.format": "--format supports text, json or fleetops",
    "cli.error.lang": "--lang supports ru or en",
    "cli.error.report_once": "--report and --append-report can be given only once",
    "cli.error.json_append": "--append-report cannot be combined with JSON output; use a separate file",
    "cli.error.json_interactive": "--interactive cannot be combined with JSON output",
    "cli.error.period": "--from cannot be later than --to",
    "cli.error.ports": "MAIL_AUDIT_ALLOWED_PORTS contains an invalid port: {value}",
    "cli.error.unknown_option": "unknown option: {option}",
    "cli.error.report": "{message}",
    "cli.error.lock": "another mail-sec-audit run holds {path}; try again later",
    "report.error.parent": "cannot create the report directory: {path}",
    "report.error.symlink": "refusing a symbolic link as report path: {path}",
    "report.error.exists": "the file already exists; use --append-report: {path}",
    "report.error.create": "cannot create the report safely: {path} ({detail})",
    "report.error.append_missing": "--append-report needs an existing regular file: {path}",
    "report.error.append_unsafe": "refusing to append: {path} ({detail})",
    "report.error.write": "cannot write the report: {path} ({detail})",
    "signal.stopped": "Stopped by signal {signal}; temporary files removed.",
    # --- terminal ---------------------------------------------------------------
    "ui.title": "MAIL SECURITY AUDIT",
    "ui.banner.host": "host",
    "ui.banner.period": "period",
    "ui.status.OK": "  OK  ",
    "ui.status.INFO": " INFO ",
    "ui.status.WARN": " WARN ",
    "ui.status.FAIL": " FAIL ",
    "ui.status.UNKNOWN": " UNKN ",
    "ui.status.N/A": " N/A  ",
    "ui.evidence": "source",
    "ui.next": "next",
    "ui.reason": "reason",
    "ui.summary": "Summary",
    "ui.result.critical": "RESULT: CRITICAL - fix FAIL first, then WARN",
    "ui.result.review": "RESULT: REVIEW REQUIRED - no critical problems",
    "ui.result.unknown": "RESULT: INCOMPLETE - some checks returned UNKNOWN; review them manually",
    "ui.result.clean": "RESULT: CLEAN - no obvious problems found",
    "ui.completeness": "Data sources",
    "ui.completeness.none": "all queried sources were readable",
    "ui.probes.local": "Local probes",
    "ui.probes.external": "External queries",
    "ui.probes.none": "none",
    "ui.no_data": "no data",
    "ui.ctx.date": "Date",
    "ui.ctx.host": "Host",
    "ui.ctx.mail_host": "FQDN / TLS name",
    "ui.ctx.domain": "Mail domain",
    "ui.ctx.domain_none": "(not specified)",
    "ui.ctx.platform": "Platform",
    "ui.ctx.period": "Analysis period",
    "ui.ctx.kernel": "Kernel",
    "ui.ctx.os": "OS",
    "ui.ctx.mta": "MTA",
    "ui.ctx.imap": "IMAP/POP3",
    "ui.ctx.lang": "Language",
    "ui.table.rank": "#",
    "ui.table.events": "EVENTS",
    "ui.table.source_ip": "SOURCE IP",
    "ui.table.mailbox": "MAILBOX / SENDER",
    "ui.table.submitted": "SUBMITTED",
    "ui.table.delivered": "DELIVERED",
    "ui.table.recipients": "RECIPIENTS",
    "ui.table.bytes": "BYTES",
    "ui.table.domain": "DOMAIN",
    "ui.table.count": "COUNT",
    "source.state.ok": "read",
    "source.state.missing": "not present",
    "source.state.denied": "permission denied",
    "source.state.timeout": "timed out",
    "source.state.truncated": "truncated at the size limit",
    "source.state.error": "error",
    "source.state.empty": "empty",
    # --- sections ---------------------------------------------------------------
    "section.CTX": "AUDIT CONTEXT",
    "section.PATCH": "PATCHES / REBOOT",
    "section.STACK": "MAIL PLATFORM / SERVICES",
    "section.SSH": "SSHD EFFECTIVE CONFIG",
    "section.NET": "LISTENING PORTS / PUBLIC BINDS",
    "section.FW": "FIREWALL",
    "section.BRUTE": "BRUTE-FORCE PROTECTION",
    "section.AUTH": "AUTHENTICATION EVENTS",
    "section.FLOW": "MAIL FLOW ANALYTICS",
    "section.MTA": "MTA / RELAY CONFIGURATION",
    "section.TLS": "TLS",
    "section.DNS": "DNS / MAIL AUTHENTICATION RECORDS",
    "section.USERS": "LOCAL USERS / PRIVILEGES",
    "section.KEYS": "SSH AUTHORIZED_KEYS",
    "section.DISK": "DISK / FILESYSTEM CAPACITY",
    "section.QUEUE": "MAIL QUEUE",
    "section.SUID": "SUID / SGID",
    "section.PERMS": "WORLD-WRITABLE PATHS",
    "section.MAC": "FAILED SERVICES / SECURITY FRAMEWORK",
    "section.SCHED": "CRON / SYSTEMD TIMERS",
    "section.BACKUP": "BACKUP DETECTION",
    "section.LOGIN": "LAST LOGINS",
    "section.PKG": "DEEP PACKAGE INTEGRITY",
    "section.RECENT": "RECENTLY MODIFIED FILES",
    "section.SUMMARY": "SUMMARY",
    # --- generic UNKNOWN / N/A --------------------------------------------------
    "common.unknown.missing_tool": "Not checked: {tool} is not installed",
    "common.unknown.permission_denied": "Not checked: no permission to read {source}",
    "common.unknown.timeout": "Not checked: {source} did not finish in time",
    "common.unknown.truncated": "Incomplete: {source} exceeded the output limit",
    "common.unknown.no_data": "No data: {source} returned nothing usable",
    "common.unknown.command_failed": "Not checked: {source} failed ({detail})",
    "common.unknown.parse_error": "Not checked: output of {source} was not recognised",
    "common.unknown.internal_error": "Check failed internally ({detail}); the rest of the report is unaffected",
    "common.na.not_applicable": "Not applicable: {detail}",
    "common.na.not_requested": "Not requested: {detail}",
    "common.next.unknown": "Run the audit as root or install the missing tool, then repeat this check.",
    "common.next.internal_error": "Report the error with the JSON report attached; check this item manually.",
    # --- CTX --------------------------------------------------------------------
    "ctx.privileges.ok": "Running as root: all local checks are available",
    "ctx.privileges.warn": "Not running as root: checks that need root return UNKNOWN",
    "ctx.privileges.next": "Run the audit with sudo for complete results.",
    "ctx.fqdn.ok": "Host name {name} looks like an FQDN",
    "ctx.fqdn.warn": "Host name {name} does not look like an FQDN",
    "ctx.fqdn.next": "Set the mail host name to a fully qualified name that matches PTR and the certificate.",
    "ctx.platform.info": "Platform: {platform} {version}",
    "interactive.no_tty": "Interactive menu skipped: stdin or stdout is not a terminal",
    "interactive.need_root": "Fail2ban management needs root",
    "interactive.unavailable": "Fail2ban does not answer; the menu is not opened",
    "interactive.title": "FAIL2BAN ACTIONS - changes only after confirmation",
    "interactive.menu.ban": "  1) Ban one address in a selected jail",
    "interactive.menu.unban": "  2) Unban an address in all jails",
    "interactive.menu.show": "  3) Show current bans",
    "interactive.menu.exit": "  0) Exit without changes",
    "interactive.prompt.action": "Action: ",
    "interactive.prompt.choice": "Choice [0=cancel]: ",
    "interactive.prompt.jail": "Jail number [0=cancel]: ",
    "interactive.prompt.unban": "Address to unban: ",
    "interactive.candidates": "Candidates from this report:",
    "interactive.manual": "   m) enter an address manually",
    "interactive.unknown_choice": "Unknown menu item",
    "interactive.cancelled": "Cancelled",
    "interactive.no_jails": "Fail2ban reported no jails",
    "interactive.will_run": "Will run: {command}",
    "interactive.confirm": "Type {word} to confirm: ",
    "interactive.banned": "{ip} banned in jail {jail}",
    "interactive.failed": "Fail2ban could not ban {ip} in jail {jail}",
    "interactive.unbanned": "Unban of {ip} sent to Fail2ban",
    "interactive.none_banned": "No banned addresses reported",
    "interactive.refuse.invalid": "Not a valid IP address: {ip}",
    "interactive.refuse.not_global": "Refused: {ip} is not a globally routable address",
    "interactive.refuse.protected": "Refused: {ip} belongs to this host or to an open SSH session",
    "auth.table.ssh_failed": "Top source addresses - SSH failures",
    "auth.table.ssh_accepted": "Top source addresses - successful SSH logins",
    "auth.table.mail_failed": "Top source addresses - mail authentication failures",
    "flow.kv.observed": "Observed log period",
    "flow.kv.lines": "Log lines",
    "flow.kv.lines_value": "{period} in period / {scanned} scanned",
    "flow.total.outbound_messages": "Outbound messages",
    "flow.total.outbound_deliveries": "Outbound deliveries",
    "flow.total.authenticated_submissions": "Authenticated submissions",
    "flow.total.authenticated_outbound_messages": "Authenticated, delivered out",
    "flow.total.incoming_messages": "Locally delivered messages",
    "flow.total.incoming_deliveries": "Local deliveries",
    "flow.total.bounced_deliveries": "Bounced attempts",
    "flow.total.deferred_deliveries": "Deferred attempts",
    "flow.total.internal_hops": "Content-filter hops (not counted)",
    "flow.total.outbound_bytes": "Outbound bytes (queue size)",
    "flow.table.users": "Top authenticated SMTP users",
    "flow.table.senders": "Top envelope senders (delivered out)",
    "flow.table.sender_domains": "Top sender domains (messages delivered out)",
    "flow.table.recipient_domains": "Top recipient domains (external deliveries)",
    "flow.table.incoming_domains": "Top sender domains of locally delivered mail",
}
