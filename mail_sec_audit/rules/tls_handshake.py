"""TLS.HANDSHAKE: TLS handshake on local mail and web listeners"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Union

from ..facts.base import Unavailable
from ..facts.tls import Target
from ..model import Finding
from .base import Builder, Check, Ctx, ev


def _targets(ctx: Ctx) -> Union[list[Target], Finding]:
    targets = ctx.facts.tls_targets()
    if isinstance(targets, Unavailable):
        return B.unavailable(targets)
    if not targets:
        return B.na("na")
    return targets


CHECK = Check("TLS.HANDSHAKE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    targets = _targets(ctx)
    if isinstance(targets, Finding):
        return [targets]
    findings = []
    for target in targets:
        result = ctx.facts.handshake(target)
        subject = str(target.port)
        evidence = [ev(f"tls:{target.label}", result.protocol or result.error)]
        if result.ok:
            findings.append(B.ok(subject=subject, port=target.port, protocol=result.protocol, evidence=evidence))
        else:
            findings.append(B.warn(subject=subject, port=target.port, error=result.error or "-", evidence=evidence))
    return findings
