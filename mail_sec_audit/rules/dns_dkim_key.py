"""DNS.DKIM_KEY: DKIM key strength"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..facts.dns import dkim_key
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("DNS.DKIM_KEY")
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
    records = [r for r in answer.records if "p=" in r]
    if not records:
        return [B.na("no_key")]
    algorithm, bits = dkim_key(records[0])
    evidence = [ev(answer.source, f"{algorithm} {bits or ''}".strip())]
    if algorithm == "ed25519":
        return [B.ok("ed25519", evidence=evidence)]
    if algorithm == "revoked":
        return [B.na("no_key")]
    if algorithm != "rsa" or bits is None:
        return [B.unknown("parse_error", source=answer.source)]
    if bits < 1024:
        return [B.fail(bits=bits, evidence=evidence)]
    if bits < 2048:
        return [B.warn(bits=bits, evidence=evidence)]
    return [B.ok(bits=bits, evidence=evidence)]
