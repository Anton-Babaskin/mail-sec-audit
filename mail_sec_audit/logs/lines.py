"""Syslog header after the timestamp: optional host name, program tag, pid.

Handles both Mail-in-a-Box line shapes in ``/var/log/mail.log``: Postfix via
syslog (``host postfix/smtpd[12]: ...``) and Dovecot writing directly without
a host name (``lmtp(user@example.com)<12><session>: Info: ...``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

HEADER_RE = re.compile(r"(?:(?P<host>[^\s\[\]:]+)\s+)?(?P<tag>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
POSTFIX_PROCESSES = frozenset(
    {
        "smtpd",
        "smtp",
        "lmtp",
        "qmgr",
        "cleanup",
        "pickup",
        "local",
        "virtual",
        "pipe",
        "error",
        "bounce",
        "postscreen",
        "submission",
        "discard",
        "retry",
    }
)
DOVECOT_LOGIN = re.compile(r"^(?:dovecot: )?(?P<service>imap-login|pop3-login|submission-login|managesieve-login): ")


@dataclass(frozen=True)
class Header:
    host: str
    tag: str
    pid: str
    message: str

    @property
    def postfix_process(self) -> Optional[str]:
        """``smtp`` for ``postfix/smtp`` or ``enforced-tls-smtp/smtp``; None otherwise.

        Mailcow sets syslog_name values without the ``postfix/`` prefix
        (``haproxy``, ``enforced-tls-smtp``, ``watchdog``), so any prefix is
        accepted as long as the last component is a Postfix process and there
        is at least one slash (OpenSMTPD logs ``smtpd[pid]`` without one).
        """
        if "/" not in self.tag:
            return None
        process = self.tag.rsplit("/", 1)[1]
        return process if process in POSTFIX_PROCESSES else None

    @property
    def watchdog(self) -> bool:
        return self.tag.startswith("watchdog/")


def parse_header(rest: str) -> Optional[Header]:
    # Direct Dovecot format: the tag itself contains parentheses and angle brackets.
    head, sep, msg = rest.partition(": ")
    if sep and " " not in head and ("(" in head or "<" in head):
        return Header("", head, "", msg)
    match = HEADER_RE.match(rest)
    if not match:
        return None
    return Header(match.group("host") or "", match.group("tag"), match.group("pid") or "", match.group("msg"))
