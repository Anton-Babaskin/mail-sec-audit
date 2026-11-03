"""BACKUP.INDICATORS: local signs of backup tooling and jobs"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("BACKUP.INDICATORS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    found = ctx.facts.backup()
    lines = [f"tool {t}" for t in found.tools] + [f"job {j}" for j in found.jobs] + [f"path {h}" for h in found.hints]
    if lines:
        return [B.info(count=len(lines), evidence=[ev("file:/etc/cron.*,/etc/systemd/system", *lines, limit=40)])]
    return [B.warn(evidence=[ev("file:/etc/cron.*,/etc/systemd/system", "no backup tool, job or path found")])]
