"""DNS.DKIM: the DKIM key for the selector is published"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.dns import dkim_key
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.DKIM")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    domain = ctx.config.mail_domain
    if not domain:
        return [B.na("na", reason=Reason.NOT_REQUESTED)]

    selector = ctx.config.dkim_selector
    if not selector:
        return [B.na("no_selector", reason=Reason.NOT_REQUESTED)]
    answer = ctx.facts.dns("TXT", f"{selector}._domainkey.{domain}")
    if isinstance(answer, Unavailable):
        return [B.unavailable(answer)]
    records = [r for r in answer.records if "p=" in r or r.lower().startswith("v=dkim1")]
    if not records:
        return [B.warn(selector=selector, evidence=[ev(answer.source, answer.rcode)])]
    algorithm, _bits = dkim_key(records[0])
    if algorithm == "revoked":
        return [B.warn("revoked", selector=selector, evidence=[ev(answer.source, records[0])])]
    return [B.ok(selector=selector, evidence=[ev(answer.source, records[0][:200])])]
