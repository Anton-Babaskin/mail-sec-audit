"""File system scans with ``find``: SUID, world-writable, recent changes.

Each scan has a timeout and an output limit; a partial result is marked
``complete=False`` and the rule reports UNKNOWN or a partial finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from ..runner import ExecState, Runner
from .base import Unavailable, from_result

SUID_STANDARD = [
    "find",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
    "-xdev",
    "-type",
    "f",
    "-perm",
    "-4000",
    "-print0",
]
SUID_USER_DIRS = [
    "find",
    "/home",
    "/root",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "-xdev",
    "-type",
    "f",
    "-perm",
    "-4000",
    "-print0",
]
WORLD_WRITABLE = [
    "find",
    "/etc",
    "/usr/local",
    "/opt",
    "-xdev",
    "(",
    "-type",
    "f",
    "-o",
    "-type",
    "d",
    ")",
    "-perm",
    "-0002",
    "-printf",
    "%y %m %p\\0",
]
FULL_SUID = [
    "find",
    "/",
    "-xdev",
    "(",
    "-path",
    "/proc",
    "-o",
    "-path",
    "/var/lib/docker",
    "-o",
    "-path",
    "/var/lib/containers",
    ")",
    "-prune",
    "-o",
    "-type",
    "f",
    "(",
    "-perm",
    "-4000",
    "-o",
    "(",
    "-perm",
    "-2000",
    "-perm",
    "/0111",
    ")",
    ")",
    "-print0",
]
RECENT = [
    "find",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
    "/etc/systemd/system",
    "/etc/cron.d",
    "-xdev",
    "-type",
    "f",
    "-mtime",
    "-30",
    "-printf",
    "%T@ %m %u:%g %p\\0",
]


@dataclass(frozen=True)
class Scan:
    entries: tuple[str, ...]
    complete: bool
    source: str


def run(runner: Runner, argv: list[str]) -> Union[Scan, Unavailable]:
    result = runner.run(argv)
    entries = tuple(e for e in result.stdout.split("\0") if e)
    # find exits 1 when some directories are unreadable or missing; keep what it printed.
    if result.state in (ExecState.OK, ExecState.NONZERO) and (result.ok or entries or result.stderr):
        complete = result.ok or "Permission denied" not in result.stderr
        return Scan(entries, complete, f"cmd:{result.display}")
    if result.state is ExecState.TRUNCATED or (result.state is ExecState.TIMEOUT and entries):
        return Scan(entries, False, f"cmd:{result.display}")
    return from_result(result)
