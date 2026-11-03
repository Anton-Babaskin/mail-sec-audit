"""STACK.CONTAINERS_HEALTH: containers of the compose project are healthy"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.docker import project_containers
from ..model import Finding
from .base import Builder, Check, Ctx, ev

CHECK = Check("STACK.CONTAINERS_HEALTH")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    if not stack.compose_project:
        return [B.na("na")]
    rows = project_containers(ctx.facts.runner, stack.compose_project)
    if rows is None:
        return [B.unknown("command_failed", source="cmd:docker ps")]
    bad = [
        f"{name}: {state} {status}"
        for name, state, status in rows
        if state in ("restarting", "exited", "dead") or "unhealthy" in status
    ]
    if bad:
        return [B.fail(count=len(bad), evidence=[ev("cmd:docker ps", *bad, limit=30)])]
    return [B.ok(count=len(rows), evidence=[ev("cmd:docker ps", *(f"{n}: {s}" for n, s, _ in rows), limit=40)])]
