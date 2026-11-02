"""QUEUE.SIZE: mail queue size"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("QUEUE.SIZE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    size = ctx.facts.queue()
    if isinstance(size, Unavailable):
        if size.reason == Reason.NOT_APPLICABLE:
            return [B.na("na")]
        return [B.unavailable(size)]
    evidence = [ev(size.source, f"queued messages: {size.count}", *size.sample)]
    if size.count > 1000:
        return [B.fail(count=size.count, evidence=evidence)]
    if size.count > 100:
        return [B.warn(count=size.count, evidence=evidence)]
    return [B.ok(count=size.count, evidence=evidence)]
