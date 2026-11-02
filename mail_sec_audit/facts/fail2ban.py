"""Fail2ban server state and jails."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Union

from ..runner import Runner
from .base import Unavailable, from_result


@dataclass(frozen=True)
class Jail:
    name: str
    banned: Optional[int]
    total: Optional[int]


@dataclass(frozen=True)
class Fail2ban:
    responding: bool
    jails: tuple[Jail, ...]
    source: str


@dataclass(frozen=True)
class NotInstalled:
    source: str = "cmd:fail2ban-client"


def _count(label: str, text: str) -> Optional[int]:
    match = re.search(rf"{label}:\s*(\d+)", text)
    return int(match.group(1)) if match else None


def collect(runner: Runner) -> Union[Fail2ban, NotInstalled, Unavailable]:
    if runner.which("fail2ban-client") is None:
        return NotInstalled()
    ping = runner.run(["fail2ban-client", "ping"])
    if not ping.ok:
        unavailable = from_result(ping)
        if unavailable.reason != "permission_denied" and "pong" not in ping.stdout.lower():
            return Fail2ban(False, (), f"cmd:{ping.display}")
        return unavailable
    if "pong" not in ping.stdout.lower():
        return Fail2ban(False, (), f"cmd:{ping.display}")
    status = runner.run(["fail2ban-client", "status"])
    if not status.ok:
        return from_result(status)
    match = re.search(r"Jail list:\s*(.*)", status.stdout)
    names = [n.strip() for n in match.group(1).split(",") if n.strip()] if match else []
    jails = []
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            continue
        detail = runner.run(["fail2ban-client", "status", name])
        text = detail.stdout if detail.ok else ""
        jails.append(Jail(name, _count("Currently banned", text), _count("Total banned", text)))
    return Fail2ban(True, tuple(jails), f"cmd:{status.display}")
