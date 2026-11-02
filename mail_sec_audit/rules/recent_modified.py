"""RECENT.MODIFIED: --deep: files changed in the last 30 days in sensitive paths"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.scans import RECENT
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("RECENT.MODIFIED", deep=True)
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    scan = ctx.facts.scan("recent", RECENT)
    if isinstance(scan, Unavailable):
        return [B.unavailable(scan)]
    entries = sorted(scan.entries, reverse=True)
    lines = []
    for entry in entries:
        stamp, _, rest = entry.partition(" ")
        try:
            when = dt.datetime.fromtimestamp(float(stamp), dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
        except ValueError:
            when = stamp
        lines.append(f"{when} {rest}")
    return [B.info(count=len(entries), evidence=[ev(scan.source, *lines, limit=100)])]
