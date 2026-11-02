"""Rule registry. One check per module, listed explicitly in report order."""

from __future__ import annotations

import time
import traceback
from collections.abc import Sequence

from ..model import Finding, Reason
from . import ctx_fqdn, ctx_privileges
from .base import Builder, Ctx, RuleModule

SECTIONS = (
    "CTX",
    "PATCH",
    "STACK",
    "SSH",
    "NET",
    "FW",
    "BRUTE",
    "AUTH",
    "FLOW",
    "MTA",
    "TLS",
    "DNS",
    "USERS",
    "KEYS",
    "DISK",
    "QUEUE",
    "SUID",
    "PERMS",
    "MAC",
    "SCHED",
    "BACKUP",
    "LOGIN",
    "PKG",
    "RECENT",
)

REGISTRY: tuple[RuleModule, ...] = (
    ctx_privileges,
    ctx_fqdn,
)


def run_checks(ctx: Ctx, modules: Sequence[RuleModule] = REGISTRY) -> list[Finding]:
    """Run every applicable rule; a crashing rule becomes UNKNOWN."""
    findings: list[Finding] = []
    durations: dict[str, int] = ctx.extra.setdefault("durations", {})
    for module in modules:
        check = module.CHECK
        if check.deep and not ctx.config.deep:
            continue
        started = time.monotonic()
        try:
            findings.extend(module.run(ctx))
        except Exception as exc:  # noqa: BLE001 - one failing check must not stop the report
            frame = traceback.extract_tb(exc.__traceback__)[-1] if exc.__traceback__ else None
            where = f" at {frame.filename.rsplit('/', 1)[-1]}:{frame.lineno}" if frame else ""
            findings.append(
                Builder(check).unknown(
                    Reason.INTERNAL_ERROR, source=f"rule:{check.id}", detail=f"{type(exc).__name__}{where}"
                )
            )
        durations[check.id] = durations.get(check.id, 0) + int((time.monotonic() - started) * 1000)
    return findings
