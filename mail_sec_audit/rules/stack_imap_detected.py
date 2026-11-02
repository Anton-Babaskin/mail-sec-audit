"""STACK.IMAP_DETECTED: an IMAP/POP3 server is present"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("STACK.IMAP_DETECTED")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    if stack.imap == "none":
        return [B.info("none", evidence=[ev("stack:detect", "no Dovecot or Courier found")])]
    return [B.info(imap=stack.imap, evidence=[ev("stack:detect", f"imap {stack.imap}")])]
