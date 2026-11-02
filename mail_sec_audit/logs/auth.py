"""Authentication failures for SSH and mail.

SSH: ``Failed <method> for`` lines are failed authentications;
``Invalid user`` lines are counted separately (they precede a Failed line
for the same attempt). Source addresses come from ``from <ip>``.

Mail: Dovecot login processes (``auth failed, N attempts``) count N failures
from ``rip=`` only (``lip=`` is this server). ``Aborted login (no auth
attempts)`` is not a failure. Postfix ``SASL ... authentication failed``
counts one failure from the bracketed client address. ``auth:`` worker
lines are not counted to avoid double counting.
"""

from __future__ import annotations

import collections
import ipaddress
import re
from typing import Optional

from .lines import DOVECOT_LOGIN, Header
from .postfix import sasl_failure_ip

SSH_FAILED = re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?\S* ?from (\S+)")
SSH_INVALID = re.compile(r"^Invalid user .* from (\S+)")
SSH_ACCEPTED = re.compile(r"^Accepted (?:password|publickey|keyboard-interactive/pam) for \S+ from (\S+)")
DOVECOT_FAILED = re.compile(r"\(auth failed, (\d+) attempts?[^)]*\)")
RIP = re.compile(r"\brip=([0-9A-Fa-f:.]+)")


def normalize_ip(text: str) -> Optional[str]:
    text = text.strip("[](),;")
    if text.startswith("::ffff:") and "." in text:
        text = text[7:]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


class AuthCounter:
    def __init__(self) -> None:
        self.ssh_failed = 0
        self.ssh_invalid = 0
        self.ssh_accepted = 0
        self.mail_failed = 0
        self.ssh_failed_ips: collections.Counter[str] = collections.Counter()
        self.ssh_accepted_ips: collections.Counter[str] = collections.Counter()
        self.mail_failed_ips: collections.Counter[str] = collections.Counter()

    def feed_ssh(self, header: Header) -> None:
        if header.tag not in ("sshd", "sshd-session"):
            return
        message = header.message
        match = SSH_FAILED.match(message)
        if match:
            self.ssh_failed += 1
            ip = normalize_ip(match.group(1))
            if ip:
                self.ssh_failed_ips[ip] += 1
            return
        if SSH_INVALID.match(message):
            self.ssh_invalid += 1
            return
        match = SSH_ACCEPTED.match(message)
        if match:
            self.ssh_accepted += 1
            ip = normalize_ip(match.group(1))
            if ip:
                self.ssh_accepted_ips[ip] += 1

    def feed_mail(self, header: Header) -> None:
        if header.watchdog:
            return
        if header.postfix_process == "smtpd":
            raw = sasl_failure_ip(header.message)
            if raw is not None:
                self.mail_failed += 1
                ip = normalize_ip(raw)
                if ip:
                    self.mail_failed_ips[ip] += 1
            return
        text = header.message if header.tag == "dovecot" else f"{header.tag}: {header.message}"
        if not DOVECOT_LOGIN.match(text):
            return
        match = DOVECOT_FAILED.search(text)
        if not match:
            return
        attempts = max(1, int(match.group(1)))
        self.mail_failed += attempts
        rip = RIP.search(text)
        ip = normalize_ip(rip.group(1)) if rip else None
        if ip:
            self.mail_failed_ips[ip] += attempts

    @staticmethod
    def top(counter: collections.Counter[str], limit: int = 15) -> list[list[object]]:
        return [[ip, count] for ip, count in sorted(counter.items(), key=lambda x: (-x[1], x[0]))[:limit]]
