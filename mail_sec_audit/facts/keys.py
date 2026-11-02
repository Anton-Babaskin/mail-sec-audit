"""authorized_keys files from AuthorizedKeysFile and account homes."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from typing import Optional

from ..host import Host
from .accounts import Accounts


@dataclass(frozen=True)
class KeyFile:
    path: str
    user: str
    mode: int
    owner_uid: int
    expected_uid: int
    key_lines: Optional[int]

    @property
    def writable_by_others(self) -> bool:
        return bool(self.mode & (stat.S_IWGRP | stat.S_IWOTH))


@dataclass(frozen=True)
class KeyFiles:
    items: tuple[KeyFile, ...]
    patterns: tuple[str, ...]
    unreadable_homes: tuple[str, ...]


def expand(pattern: str, home: str, user: str) -> str:
    path = pattern.replace("%%", "\x00").replace("%h", home).replace("%u", user).replace("\x00", "%")
    return path if path.startswith("/") else f"{home.rstrip('/')}/{path}"


def collect(host: Host, accounts: Accounts, patterns: tuple[str, ...]) -> KeyFiles:
    patterns = patterns or (".ssh/authorized_keys", ".ssh/authorized_keys2")
    items: list[KeyFile] = []
    unreadable: list[str] = []
    seen: set[str] = set()
    for account in accounts.items:
        if not account.home.startswith("/") or account.home in ("/", "/nonexistent"):
            continue
        if not account.interactive and account.uid != 0:
            continue
        if host.is_dir(account.home) and host.listdir(account.home) is None:
            unreadable.append(account.home)
            continue
        for pattern in patterns:
            if pattern.lower() == "none":
                continue
            path = expand(pattern, account.home, account.name)
            if path in seen or not host.is_regular(path):
                continue
            seen.add(path)
            info = host.lstat(path)
            if info is None:
                continue
            read = host.read_text(path, 1024 * 1024)
            lines = None
            if read.ok:
                lines = sum(1 for line in read.text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
            items.append(KeyFile(path, account.name, stat.S_IMODE(info.st_mode), info.st_uid, account.uid, lines))
    return KeyFiles(tuple(items), patterns, tuple(unreadable))
