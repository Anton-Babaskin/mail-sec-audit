"""DNS.MX: MX records for the mail domain"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.MX")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    domain = ctx.config.mail_domain
    if not domain:
        return [B.na("na", reason=Reason.NOT_REQUESTED)]

    answer = ctx.facts.dns("MX", domain)
    if isinstance(answer, Unavailable):
        return [B.unavailable(answer)]
    if answer.absent:
        return [B.warn(domain=domain, evidence=[ev(answer.source, answer.rcode)])]
    return [B.ok(domain=domain, count=len(answer.records), evidence=[ev(answer.source, *answer.records)])]
