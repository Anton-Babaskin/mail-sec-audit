"""TLS.DOVECOT_MIN_PROTOCOL: Dovecot ssl_min_protocol is TLS 1.2 or newer"""

from __future__ import annotations

from collections.abc import Iterable

from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("TLS.DOVECOT_MIN_PROTOCOL")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    if ctx.facts.stack().imap != "dovecot":
        return [B.na("na")]
    settings = ctx.facts.dovecot()
    if settings.failure is not None:
        return [B.unavailable(settings.failure)]
    value = settings.values.get("ssl_min_protocol")
    evidence = [ev(settings.source, f"ssl_min_protocol = {value}", f"ssl = {settings.values.get('ssl')}")]
    if value is None:
        return [B.unknown("parse_error", source=settings.source)]
    if value in ("TLSv1.2", "TLSv1.3"):
        return [B.ok(value=value, evidence=evidence)]
    return [B.warn(value=value or "(empty)", evidence=evidence)]
