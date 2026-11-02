"""STACK.MTA_DETECTED: a mail transfer agent is present"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("STACK.MTA_DETECTED")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    if stack.mta == "none":
        return [B.fail(evidence=[ev("stack:detect", "no Postfix, Exim, OpenSMTPD or Sendmail found")])]
    return [B.info(mta=stack.mta, evidence=[ev("stack:detect", f"mta {stack.mta}")])]
