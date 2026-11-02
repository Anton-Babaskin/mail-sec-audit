"""TLS.LEGACY_PROTOCOLS: --deep: TLS 1.0 and 1.1 are refused"""

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


CHECK = Check("TLS.LEGACY_PROTOCOLS", deep=True)
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
        results = {version: ctx.facts.legacy_tls(target, version) for version in ("TLSv1", "TLSv1.1")}
        evidence = [ev(f"tls:{target.label}", *(f"{v}: {r}" for v, r in results.items()))]
        accepted = [v for v, r in results.items() if r == "accepted"]
        if accepted and target.port == 25:
            findings.append(
                B.info(
                    "opportunistic", subject=subject, port=target.port, versions=", ".join(accepted), evidence=evidence
                )
            )
        elif accepted:
            findings.append(B.warn(subject=subject, port=target.port, versions=", ".join(accepted), evidence=evidence))
        elif all(r == "rejected" for r in results.values()):
            findings.append(B.ok(subject=subject, port=target.port, evidence=evidence))
        else:
            unclear = next(r for r in results.values() if r != "rejected")
            reason = "missing_tool" if unclear == "client_unsupported" else "command_failed"
            findings.append(
                B.unknown(
                    reason,
                    source=f"tls:{target.label}",
                    subject=subject,
                    detail=unclear,
                    tool="python ssl TLSv1",
                    evidence=evidence,
                )
            )
    return findings
