"""MTA.OPENSMTPD_RELAY: OpenSMTPD does not relay from any to any without auth"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("MTA.OPENSMTPD_RELAY")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().mta != "opensmtpd":
        return [B.na("na")]
    conf = ctx.facts.opensmtpd()
    if isinstance(conf, Unavailable):
        return [B.unavailable(conf)]
    if conf.open_matches:
        return [B.fail(evidence=[ev(f"file:{conf.path}", *conf.open_matches)])]
    return [B.info(evidence=[ev(f"file:{conf.path}", *(f"relay action {a}" for a in conf.relay_actions))])]
