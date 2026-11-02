"""DNS.DMARC: DMARC policy is quarantine or reject"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.DMARC")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    domain = ctx.config.mail_domain
    if not domain:
        return [B.na("na", reason=Reason.NOT_REQUESTED)]

    answer = ctx.facts.dns("TXT", f"_dmarc.{domain}")
    if isinstance(answer, Unavailable):
        return [B.unavailable(answer)]
    records = [r for r in answer.records if r.lower().startswith("v=dmarc1")]
    if not records:
        return [B.warn("missing", domain=domain, evidence=[ev(answer.source, answer.rcode)])]
    match = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", records[0], re.IGNORECASE)
    policy = match.group(1).lower() if match else ""
    evidence = [ev(answer.source, *records)]
    if policy in ("reject", "quarantine"):
        return [B.ok(policy=policy, evidence=evidence)]
    if policy == "none":
        return [B.warn("monitor", evidence=evidence)]
    return [B.warn("unparsed", evidence=evidence)]
