"""Effective sshd configuration from ``sshd -T``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from ..host import Host
from ..runner import Runner
from .base import Unavailable, from_result


@dataclass(frozen=True)
class SshdConfig:
    values: dict[str, tuple[str, ...]]
    source: str
    has_match_blocks: bool

    def get(self, key: str) -> Optional[str]:
        found = self.values.get(key)
        return found[0] if found else None

    def all(self, key: str) -> tuple[str, ...]:
        return self.values.get(key, ())


@dataclass(frozen=True)
class NotInstalled:
    source: str = "cmd:sshd"


def collect(host: Host, runner: Runner) -> Union[SshdConfig, NotInstalled, Unavailable]:
    if runner.which("sshd") is None:
        return NotInstalled()
    result = runner.run(["sshd", "-T"])
    if not result.ok:
        return from_result(result)
    values: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            values.setdefault(key.lower(), []).append(value.strip())
    if "permitrootlogin" not in values or "passwordauthentication" not in values:
        return Unavailable("parse_error", f"cmd:{result.display}")
    match_blocks = False
    for path in ["/etc/ssh/sshd_config", *host.glob("/etc/ssh/sshd_config.d/*.conf")]:
        read = host.read_text(path, 256 * 1024)
        if read.ok and any(line.strip().lower().startswith("match ") for line in read.text.splitlines()):
            match_blocks = True
    return SshdConfig({k: tuple(v) for k, v in values.items()}, f"cmd:{result.display}", match_blocks)
