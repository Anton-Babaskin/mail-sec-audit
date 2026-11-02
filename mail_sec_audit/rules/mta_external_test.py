"""MTA.EXTERNAL_TEST: an external open-relay test is still needed"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MTA.EXTERNAL_TEST")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().mta == "none":
        return [B.na("na")]
    return [B.info(evidence=[ev("note", "local configuration cannot prove the absence of an open relay")])]
