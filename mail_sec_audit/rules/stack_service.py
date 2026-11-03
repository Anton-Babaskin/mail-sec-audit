"""STACK.SERVICE: required mail services are running"""

from __future__ import annotations

from collections.abc import Iterable

from ..facts.base import Unavailable
from ..model import Finding, Reason
from .base import Builder, Check, Ctx, ev

CHECK = Check("STACK.SERVICE")
B = Builder(CHECK)


def run(ctx: Ctx) -> Iterable[Finding]:
    stack = ctx.facts.stack()
    findings: list[Finding] = []
    units = ctx.facts.units()
    for service in stack.services:
        if service.kind == "container":
            state = stack.container_states.get(service.name)
            evidence = [ev("cmd:docker ps", f"{service.name}: {state or 'not found'}")]
            if state == "running":
                findings.append(B.ok(subject=service.name, name=service.name, evidence=evidence))
            else:
                findings.append(
                    B.fail(subject=service.name, name=service.name, state=state or "not found", evidence=evidence)
                )
            continue
        if isinstance(units, Unavailable):
            if units.reason == Reason.NOT_APPLICABLE:
                findings.append(B.na("na", subject=service.name))
            else:
                findings.append(B.unavailable(units, subject=service.name))
            continue
        if not units.known(service.name):
            if service.required:
                findings.append(
                    B.fail(
                        subject=service.name,
                        name=service.name,
                        state="not installed",
                        evidence=[ev(units.source, f"{service.name}: not-found")],
                    )
                )
            continue
        active = units.states.get(service.name, {}).get("ActiveState", "unknown")
        evidence = [ev(units.source, f"{service.name}: {active}")]
        if active == "active":
            findings.append(B.ok(subject=service.name, name=service.name, evidence=evidence))
        elif service.fail_status == "FAIL":
            findings.append(B.fail(subject=service.name, name=service.name, state=active, evidence=evidence))
        else:
            findings.append(B.warn(subject=service.name, name=service.name, state=active, evidence=evidence))
    return findings
