"""LOGIN.RECENT: recent successful and failed logins (inventory)"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Output, Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("LOGIN.RECENT")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    last = ctx.facts.command(["last", "-a", "-w", "-n", "20"])
    lastb = ctx.facts.command(["lastb", "-a", "-w", "-n", "20"])
    evidence = []
    for out in (last, lastb):
        if isinstance(out, Output):
            evidence.append(ev(out.source, *out.lines, limit=20))
    if not evidence and isinstance(last, Unavailable):
        return [B.unavailable(last)]
    findings = [B.info(evidence=evidence)]
    if isinstance(lastb, Unavailable) and lastb.reason != "missing_tool":
        findings.append(B.unavailable(lastb, subject="lastb"))
    return findings
