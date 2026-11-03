"""DNS.SPF: exactly one SPF record"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.SPF")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    domain = ctx.config.mail_domain
    if not domain:
        return [B.na("na", reason=Reason.NOT_REQUESTED)]

    answer = ctx.facts.dns("TXT", domain)
    if isinstance(answer, Unavailable):
        return [B.unavailable(answer)]
    spf = [r for r in answer.records if r.lower().startswith("v=spf1")]
    evidence = [ev(answer.source, *spf)]
    if not spf:
        return [B.warn(domain=domain, evidence=[ev(answer.source, answer.rcode)])]
    if len(spf) > 1:
        return [B.fail("multiple", count=len(spf), evidence=evidence)]
    return [B.ok(evidence=evidence)]
