"""Redaction for --redact.

Covers: e-mail addresses, IPv4 and IPv6 addresses (validated with
``ipaddress``, so clock times and ``APT::Periodic`` stay intact), the audited
host names and mail domain with their subdomains, and local account names
with UID >= 1000. Mail statistics use per-run keyed pseudonyms.

Not covered: third-party host names in evidence (remote PTR names, relay
host names), certificate subjects of other names, device paths. Review a
report before sharing it.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Iterable

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]{0,15}(?![0-9A-Za-z:])")


def _ipv4(match: re.Match[str]) -> str:
    try:
        ipaddress.IPv4Address(match.group(0))
    except ValueError:
        return match.group(0)
    return "<redacted-ip>"


def _ipv6(match: re.Match[str]) -> str:
    text = match.group(0)
    try:
        ipaddress.IPv6Address(text.strip("[]"))
    except ValueError:
        return text
    return "<redacted-ipv6>"


class Redactor:
    def __init__(self, names: Iterable[str] = (), users: Iterable[str] = (), *, enabled: bool = True) -> None:
        self.enabled = enabled
        self.key = secrets.token_bytes(32)
        cleaned = sorted({n.lower().rstrip(".") for n in names if n and "." in n}, key=len, reverse=True)
        self._names = (
            re.compile(
                r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)*(?:"
                + "|".join(re.escape(n) for n in cleaned)
                + r")\.?(?![A-Za-z0-9-])",
                re.IGNORECASE,
            )
            if cleaned
            else None
        )
        short = sorted({u for u in users if len(u) >= 3}, key=len, reverse=True)
        self._users = (
            re.compile(r"(?<![A-Za-z0-9_.-])(?:" + "|".join(re.escape(u) for u in short) + r")(?![A-Za-z0-9_-])")
            if short
            else None
        )

    def __call__(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        text = EMAIL_RE.sub("<redacted-email>", text)
        text = IPV4_RE.sub(_ipv4, text)
        text = IPV6_RE.sub(_ipv6, text)
        if self._names is not None:
            text = self._names.sub("<redacted-host>", text)
        if self._users is not None:
            text = self._users.sub("<redacted-user>", text)
        return text

    def pseudonym(self, kind: str, value: str) -> str:
        """Stable within one report, unlinkable across reports."""
        if not self.enabled or not value or value.startswith("("):
            return value
        digest = hmac.new(self.key, value.lower().encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]
        return f"{kind}-{digest}"


NO_REDACTION = Redactor(enabled=False)
