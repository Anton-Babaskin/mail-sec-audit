"""TLS.CERT_EXPIRY: certificate validity period"""

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


CHECK = Check("TLS.CERT_EXPIRY")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    targets = _targets(ctx)
    if isinstance(targets, Finding):
        return [targets]
    findings = []
    for target in targets:
        if not ctx.facts.handshake(target).ok:
            continue
        subject = str(target.port)
        cert = ctx.facts.certificate(target)
        if isinstance(cert, Unavailable):
            findings.append(B.unavailable(cert, subject=subject))
            continue
        if cert.not_after is None:
            findings.append(B.unknown("parse_error", source=cert.source, subject=subject))
            continue
        days = int((cert.not_after - ctx.host.now()).total_seconds() // 86400)
        evidence = [
            ev(
                f"tls:{target.label}",
                f"subject {cert.subject}",
                f"issuer {cert.issuer}",
                f"notAfter {cert.not_after:%Y-%m-%d %H:%M} UTC",
            )
        ]
        port = target.port
        if days < 0:
            findings.append(B.fail("expired", port=port, days=-days, subject=subject, evidence=evidence))
        elif days < 14:
            findings.append(B.fail(port=port, days=days, subject=subject, evidence=evidence))
        elif days < 30:
            findings.append(B.warn(port=port, days=days, subject=subject, evidence=evidence))
        else:
            findings.append(B.ok(port=port, days=days, subject=subject, evidence=evidence))
    return findings
