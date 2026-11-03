"""CTX.PRIVILEGES: is the audit running as root."""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("CTX.PRIVILEGES")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    evidence = [ev("proc:euid", f"euid={ctx.host.euid}")]
    if ctx.host.euid == 0:
        return [B.ok(evidence=evidence)]
    return [B.warn(evidence=evidence)]
