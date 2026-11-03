"""Sendmail relay features from sendmail.mc (the binary is never executed
with -bv: Postfix's sendmail mails a report for -bv)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Union

from ..host import Host
from .base import Unavailable, from_file

RELAY_FEATURES = (
    "promiscuous_relay",
    "relay_entire_domain",
    "relay_based_on_MX",
    "loose_relay_check",
    "relay_local_from",
)


@dataclass(frozen=True)
class SendmailMc:
    features: tuple[str, ...]
    source: str = "file:/etc/mail/sendmail.mc"


def collect(host: Host) -> Union[SendmailMc, Unavailable]:
    read = host.read_text("/etc/mail/sendmail.mc", 512 * 1024)
    if not read.ok:
        return from_file(read)
    found = []
    for line in read.text.splitlines():
        match = re.match(r"\s*FEATURE\(\s*[`']?(\w+)", line)
        if match and match.group(1) in RELAY_FEATURES:
            found.append(match.group(1))
    return SendmailMc(tuple(found))
