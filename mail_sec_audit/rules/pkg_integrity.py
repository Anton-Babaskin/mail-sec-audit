"""PKG.INTEGRITY: --deep: package file integrity"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("PKG.INTEGRITY", deep=True)
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.runner.which("debsums"):
        out = ctx.facts.command(["debsums", "-s"])
        if isinstance(out, Unavailable):
            return [B.unavailable(out)]
        changed = [line for line in out.lines if "changed" in line or "missing" in line or "FAILED" in line]
        if changed:
            return [B.warn(count=len(changed), evidence=[ev(out.source, *changed, limit=50)])]
        return [B.ok(evidence=[ev(out.source)])]
    if ctx.facts.runner.which("rpm"):
        out = ctx.facts.command(["rpm", "-Va", "--noscripts"])
        if isinstance(out, Unavailable):
            return [B.unavailable(out)]
        binaries = [line for line in out.lines if len(line) > 11 and "5" in line[:9] and line[10] != "c"]
        if binaries:
            return [B.warn(count=len(binaries), evidence=[ev(out.source, *binaries, limit=50)])]
        if out.lines:
            return [B.info("config", count=len(out.lines), evidence=[ev(out.source, *out.lines, limit=30)])]
        return [B.ok(evidence=[ev(out.source)])]
    return [B.unknown("missing_tool", source="cmd:debsums/rpm", tool="debsums")]
