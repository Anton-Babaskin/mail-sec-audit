"""TLS.CERT_NAME: certificate matches the mail host name"""

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


CHECK = Check("TLS.CERT_NAME")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    targets = _targets(ctx)
    if isinstance(targets, Finding):
        return [targets]
    name = ctx.facts.server_name()
    findings = []
    for target in targets:
        if not ctx.facts.handshake(target).ok:
            continue
        subject = str(target.port)
        cert = ctx.facts.certificate(target)
        if isinstance(cert, Unavailable):
            findings.append(B.unavailable(cert, subject=subject))
            continue
        evidence = [ev(f"tls:{target.label}", f"subject {cert.subject}", f"checkhost {name}")]
        if cert.name_matches is True:
            findings.append(B.ok(subject=subject, port=target.port, name=name, evidence=evidence))
        elif cert.name_matches is False:
            findings.append(B.warn(subject=subject, port=target.port, name=name, evidence=evidence))
        else:
            findings.append(B.unknown("parse_error", source=cert.source, subject=subject))
    return findings
