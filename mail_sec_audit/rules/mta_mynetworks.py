"""MTA.MYNETWORKS: Postfix mynetworks does not trust the Internet"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.postfix import tokens
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MTA.MYNETWORKS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().mta != "postfix":
        return [B.na("na")]
    config = ctx.facts.postfix()
    if isinstance(config, Unavailable):
        return [B.unavailable(config)]
    value = config.effective("mynetworks")
    evidence = [ev(config.source, f"mynetworks = {value}")]
    broad = []
    for token in tokens(value):
        text = token.strip("[]").replace("]/", "/")
        if text in ("0/0", "0.0.0.0/0", "::/0"):
            return [B.fail(network=token, evidence=evidence)]
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            return [B.fail(network=token, evidence=evidence)]
        limit = 16 if network.version == 4 else 32
        if network.is_global and network.prefixlen <= limit:
            broad.append(token)
    if broad:
        return [B.warn(networks=", ".join(broad), evidence=evidence)]
    return [B.ok(evidence=evidence)]
