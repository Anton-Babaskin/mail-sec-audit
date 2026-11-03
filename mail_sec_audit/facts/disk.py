"""Filesystem and inode usage from ``df``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from ..runner import Runner
from .base import Unavailable, from_result

DF_EXCLUDES = ["-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"]


@dataclass(frozen=True)
class Usage:
    filesystem: str
    total: int
    used: int
    available: int
    percent: int
    mountpoint: str


@dataclass(frozen=True)
class DiskUsage:
    items: tuple[Usage, ...]
    source: str


def _parse(text: str) -> list[Usage]:
    items = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 5)
        if len(parts) != 6 or not parts[1].isdigit() or not parts[4].rstrip("%").isdigit():
            continue
        items.append(Usage(parts[0], int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4].rstrip("%")), parts[5]))
    return items


def space(runner: Runner) -> Union[DiskUsage, Unavailable]:
    result = runner.run(["df", "-P", "-B1", *DF_EXCLUDES])
    # df exits 1 when one mount cannot be read but still prints the others.
    if result.state.value not in ("ok", "nonzero") or not result.stdout.strip():
        return from_result(result)
    return DiskUsage(tuple(_parse(result.stdout)), f"cmd:{result.display}")


def inodes(runner: Runner) -> Union[DiskUsage, Unavailable]:
    result = runner.run(["df", "-P", "-i", *DF_EXCLUDES])
    if result.state.value not in ("ok", "nonzero") or not result.stdout.strip():
        return from_result(result)
    return DiskUsage(tuple(_parse(result.stdout)), f"cmd:{result.display}")
