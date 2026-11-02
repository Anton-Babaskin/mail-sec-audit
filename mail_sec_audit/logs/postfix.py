"""Structural parser for Postfix message bodies.

Fields are read in their fixed order instead of searched anywhere in the
line, so values inside hostile addresses (``to=<"x status=sent"@...>``,
``from=<"sasl_username=ceo"@...>``, ``size=`` in a quoted local part) or in
remote responses cannot change the result.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

SHORT_QID = re.compile(r"[0-9A-F]{5,12}")
LONG_QID = re.compile(r"[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,20}")
DELIVERY_TAIL = re.compile(
    r", relay=(?P<relay>[^,\s]+)(?:, conn_use=\d+)?, delay=[\d.]+, delays=[\d./]+, dsn=(?P<dsn>\d\.\d{1,3}\.\d{1,3}), "
    r"status=(?P<status>[a-z]+)(?: \((?P<text>.*)\))?$"
)
QMGR_TAIL = re.compile(r", size=(?P<size>\d+), nrcpt=(?P<nrcpt>\d+) \(queue active\)$")
EXPIRED_TAIL = re.compile(r", status=expired, returned to sender$")
CLIENT_RE = re.compile(
    r"client=(?P<host>[^\[\s,]*)\[(?P<ip>[^\]]+)\](?::\d+)?"
    r"(?:, sasl_method=(?P<method>[A-Za-z0-9_-]+), sasl_username=(?P<user>.+?))?(?:, sasl_sender=.*)?$"
)
SASL_FAIL_RE = re.compile(r"^warning: (?P<host>[^\[\s]*)\[(?P<ip>[^\]]+)\]: SASL [A-Za-z0-9_-]+ authentication failed")
QUEUED_AS = re.compile(r"\bqueued as (?P<qid>[0-9A-Za-z]{5,20})\b")


def split_queue_id(message: str) -> Optional[tuple[str, str]]:
    qid, sep, body = message.partition(": ")
    if sep and (SHORT_QID.fullmatch(qid) or LONG_QID.fullmatch(qid)):
        return qid, body
    return None


def take_address(text: str, prefix: str) -> Optional[tuple[str, str]]:
    """Read ``prefix<addr>`` at the start of ``text``; return (address, rest).

    Postfix quotes local parts with special characters, e.g.
    ``to=<"a>b, status=sent"@example.org>``.
    """
    if not text.startswith(prefix + "<"):
        return None
    i = len(prefix) + 1
    local_end = i
    if text[i : i + 1] == '"':
        j = i + 1
        while j < len(text):
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == '"':
                break
            j += 1
        else:
            return None
        local_end = j + 1
    end = text.find(">", local_end)
    if end < 0:
        return None
    return text[i:end], text[end + 1 :]


@dataclass(frozen=True)
class Delivery:
    recipient: str
    relay: str
    status: str
    dsn: str
    text: str

    @property
    def relay_host(self) -> str:
        return self.relay.split("[", 1)[0]

    @property
    def relay_ip(self) -> Optional[str]:
        if "[" not in self.relay:
            return None
        return self.relay.split("[", 1)[1].split("]", 1)[0]

    @property
    def loopback(self) -> bool:
        ip = self.relay_ip
        if ip is None:
            return self.relay_host in ("localhost",)
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return False

    @property
    def queued_as(self) -> Optional[str]:
        match = QUEUED_AS.search(self.text) if self.text else None
        return match.group("qid") if match else None


def parse_delivery(body: str) -> Optional[Delivery]:
    taken = take_address(body, "to=")
    if taken is None:
        return None
    recipient, rest = taken
    if rest.startswith(", orig_to="):
        orig = take_address(rest[2:], "orig_to=")
        if orig is None:
            return None
        rest = orig[1]
    match = DELIVERY_TAIL.match(rest)
    if not match:
        return None
    return Delivery(
        recipient, match.group("relay"), match.group("status"), match.group("dsn"), match.group("text") or ""
    )


@dataclass(frozen=True)
class Envelope:
    sender: str
    size: int
    nrcpt: int


def parse_qmgr(body: str) -> Optional[Envelope]:
    taken = take_address(body, "from=")
    if taken is None:
        return None
    sender, rest = taken
    match = QMGR_TAIL.match(rest)
    if not match:
        return None
    return Envelope(sender, int(match.group("size")), int(match.group("nrcpt")))


def parse_expired(body: str) -> bool:
    taken = take_address(body, "from=")
    return taken is not None and EXPIRED_TAIL.match(taken[1]) is not None


@dataclass(frozen=True)
class Client:
    host: str
    ip: str
    sasl_user: Optional[str]


def parse_client(body: str) -> Optional[Client]:
    match = CLIENT_RE.match(body)
    if not match:
        return None
    return Client(match.group("host"), match.group("ip"), match.group("user"))


def sasl_failure_ip(message: str) -> Optional[str]:
    match = SASL_FAIL_RE.match(message)
    return match.group("ip") if match else None
