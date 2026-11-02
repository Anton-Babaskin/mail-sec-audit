"""DNS.MTA_STS: MTA-STS TXT record"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.MTA_STS")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    domain = ctx.config.mail_domain
    if not domain:
        return [B.na("na", reason=Reason.NOT_REQUESTED)]

    answer = ctx.facts.dns("TXT", f"_mta-sts.{domain}")
    if isinstance(answer, Unavailable):
        return [B.unavailable(answer)]
    records = [r for r in answer.records if r.lower().startswith("v=stsv1")]
    if records:
        return [B.ok(evidence=[ev(answer.source, *records)])]
    return [B.info("missing", evidence=[ev(answer.source, answer.rcode)])]
