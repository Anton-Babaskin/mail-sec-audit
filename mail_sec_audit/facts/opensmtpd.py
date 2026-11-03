"""OpenSMTPD relay rules from smtpd.conf.

``smtpctl`` has no command that prints the configuration (smtpctl(8)), so
the file is read. A ``match from any for any`` rule that relays without
``auth`` makes an open relay.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Union

from ..host import Host
from .base import Unavailable, from_file

PATHS = ("/etc/smtpd.conf", "/etc/opensmtpd/smtpd.conf", "/usr/local/etc/smtpd.conf")


@dataclass(frozen=True)
class SmtpdConf:
    path: str
    relay_actions: tuple[str, ...]
    open_matches: tuple[str, ...]


def collect(host: Host) -> Union[SmtpdConf, Unavailable]:
    for path in PATHS:
        read = host.read_text(path, 512 * 1024)
        if read.state == "missing":
            continue
        if not read.ok:
            return from_file(read)
        lines = [line.split("#", 1)[0].strip() for line in read.text.splitlines()]
        relay_actions = tuple(
            m.group(1) for line in lines if (m := re.match(r'action\s+"?([\w-]+)"?\s+relay\b', line)) is not None
        )
        open_matches = []
        for line in lines:
            if not line.startswith("match ") or "auth" in line.split():
                continue
            action = re.search(r'action\s+"?([\w-]+)"?', line)
            if (
                action
                and action.group(1) in relay_actions
                and re.search(r"\bfrom any\b", line)
                and re.search(r"\bfor any\b", line)
            ):
                open_matches.append(line)
        return SmtpdConf(path, relay_actions, tuple(open_matches))
    return Unavailable("no_data", "file:/etc/smtpd.conf")
