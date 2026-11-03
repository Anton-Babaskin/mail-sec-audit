"""Local accounts, password status (without hashes) and sudo NOPASSWD."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Union

from ..host import Host
from ..runner import Runner
from .base import Unavailable, from_file, from_result

NOLOGIN = re.compile(r"(nologin|false|sync|shutdown|halt)$")


@dataclass(frozen=True)
class Account:
    name: str
    uid: int
    home: str
    shell: str

    @property
    def interactive(self) -> bool:
        return bool(self.shell) and not NOLOGIN.search(self.shell)


@dataclass(frozen=True)
class Accounts:
    items: tuple[Account, ...]
    source: str = "file:/etc/passwd"


@dataclass(frozen=True)
class PasswordStatus:
    empty: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class Sudoers:
    nopasswd: tuple[str, ...]
    source: str


def passwd(host: Host) -> Union[Accounts, Unavailable]:
    read = host.read_text("/etc/passwd")
    if not read.ok:
        return from_file(read)
    items = []
    for line in read.text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit():
            items.append(Account(parts[0], int(parts[2]), parts[5], parts[6]))
    return Accounts(tuple(items))


def password_status(runner: Runner, accounts: Accounts) -> Union[PasswordStatus, Unavailable]:
    """``passwd -S`` prints status letters (P, L, NP); hashes never reach us."""
    result = runner.run(["passwd", "-S", "-a"])
    lines: list[str] = []
    source = f"cmd:{result.display}"
    if result.ok:
        lines = result.stdout.splitlines()
    elif "permission" in (result.stderr + result.stdout).lower() or result.state.value == "missing":
        return from_result(result)
    else:
        # shadow-utils passwd on RHEL has no -a; ask per interactive account.
        source = "cmd:passwd -S <user>"
        for account in accounts.items:
            if not account.interactive and account.uid != 0:
                continue
            single = runner.run(["passwd", "-S", account.name])
            if not single.ok:
                return from_result(single)
            lines.extend(single.stdout.splitlines())
    empty = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "NP":
            empty.append(fields[0])
    return PasswordStatus(tuple(empty), source)


def sudoers(host: Host) -> Union[Sudoers, Unavailable]:
    paths = ["/etc/sudoers", *host.glob("/etc/sudoers.d/*")]
    found: list[str] = []
    for path in paths:
        read = host.read_text(path, 256 * 1024)
        if read.state == "denied":
            return from_file(read)
        for line in read.text.splitlines() if read.ok else []:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                found.append(f"{path}: {stripped}")
    return Sudoers(tuple(found), "file:/etc/sudoers")
