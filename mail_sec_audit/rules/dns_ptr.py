"""DNS.PTR: reverse DNS of the mail host matches its name"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.PTR")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    domain = ctx.config.mail_domain
    if not domain:
        return [B.na("na", reason=Reason.NOT_REQUESTED)]

    name = ctx.facts.server_name()
    answer = ctx.facts.dns("A", name)
    if isinstance(answer, Unavailable):
        return [B.unavailable(answer)]
    if answer.absent:
        return [B.warn("no_address", name=name, evidence=[ev(answer.source, answer.rcode)])]
    findings = []
    for ip in answer.records:
        ptr = ctx.facts.dns("PTR", ip)
        if isinstance(ptr, Unavailable):
            findings.append(B.unavailable(ptr, subject=ip))
            continue
        names = [r.rstrip(".").lower() for r in ptr.records]
        evidence = [ev(ptr.source, *(names or [ptr.rcode]))]
        if not names:
            findings.append(B.warn("missing", subject=ip, ip=ip, evidence=evidence))
        elif name.rstrip(".").lower() in names:
            findings.append(B.ok(subject=ip, ip=ip, name=name, evidence=evidence))
        else:
            findings.append(B.warn(subject=ip, ip=ip, ptr=names[0], name=name, evidence=evidence))
    return findings
