"""MTA.EXIM_RELAY_HOSTS: Exim relay_from_hosts is not open"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MTA.EXIM_RELAY_HOSTS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().mta != "exim":
        return [B.na("na")]
    options = ctx.facts.exim()
    if isinstance(options, Unavailable):
        return [B.unavailable(options)]
    value = options.values.get("relay_from_hosts", "")
    evidence = [ev(options.source, f"relay_from_hosts = {value}")]
    if re.search(r"(^|[\s:;])(0\.0\.0\.0/0|::/0|::0/0|\*)($|[\s:;])", value):
        return [B.fail(evidence=evidence)]
    return [B.info(evidence=evidence)]
