"""Building blocks for rule modules.

A rule module defines ``CHECK`` and ``run(ctx)``. It reads facts through
``ctx.facts`` and never starts processes or checks the stack name.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional, Protocol

from ..facts.base import Unavailable
from ..model import Evidence, Finding, Reason, Status

if TYPE_CHECKING:
    from ..cli import Config
    from ..facts import Facts
    from ..host import Host
    from ..model import Completeness
    from ..stacks.base import Stack


@dataclass(frozen=True)
class Check:
    id: str
    deep: bool = False

    @property
    def section(self) -> str:
        return self.id.split(".", 1)[0]

    @property
    def key(self) -> str:
        return self.id.lower()


@dataclass
class Ctx:
    config: Config
    host: Host
    facts: Facts
    completeness: Completeness
    stack: Optional[Stack] = None
    extra: dict[str, Any] = field(default_factory=dict)


class RuleModule(Protocol):
    CHECK: Check

    def run(self, ctx: Ctx) -> Iterable[Finding]: ...


class Builder:
    """Creates findings for one check with consistent keys."""

    def __init__(self, check: Check) -> None:
        self.check = check

    def _make(
        self,
        status: Status,
        outcome: str,
        *,
        subject: Optional[str] = None,
        evidence: Iterable[Evidence] = (),
        next_step: Optional[str] = None,
        reason: Optional[str] = None,
        key: Optional[str] = None,
        **params: Any,
    ) -> Finding:
        if next_step is None and status in (Status.WARN, Status.FAIL):
            next_step = f"{self.check.key}.next"
        return Finding(
            check_id=self.check.id,
            status=status,
            key=key or f"{self.check.key}.{outcome}",
            params=params,
            subject=subject,
            evidence=tuple(evidence),
            next_step=next_step,
            reason=reason,
        )

    def ok(self, outcome: str = "ok", **kw: Any) -> Finding:
        return self._make(Status.OK, outcome, **kw)

    def info(self, outcome: str = "info", **kw: Any) -> Finding:
        return self._make(Status.INFO, outcome, **kw)

    def warn(self, outcome: str = "warn", **kw: Any) -> Finding:
        return self._make(Status.WARN, outcome, **kw)

    def fail(self, outcome: str = "fail", **kw: Any) -> Finding:
        return self._make(Status.FAIL, outcome, **kw)

    def na(self, outcome: str, *, reason: str = Reason.NOT_APPLICABLE, **kw: Any) -> Finding:
        return self._make(Status.NA, outcome, reason=reason, **kw)

    def unknown(
        self,
        reason: str,
        *,
        source: str,
        detail: str = "",
        tool: str = "",
        subject: Optional[str] = None,
        evidence: Iterable[Evidence] = (),
    ) -> Finding:
        next_step = "common.next.internal_error" if reason == Reason.INTERNAL_ERROR else "common.next.unknown"
        return self._make(
            Status.UNKNOWN,
            reason,
            key=f"common.unknown.{reason}",
            subject=subject,
            evidence=tuple(evidence) or (Evidence(source),),
            next_step=next_step,
            reason=reason,
            source=source.split(":", 1)[-1],
            detail=detail or "-",
            tool=tool or source.split(":", 1)[-1].split(" ", 1)[0],
        )

    def unavailable(self, fact: Unavailable, *, subject: Optional[str] = None) -> Finding:
        return self.unknown(fact.reason, source=fact.source, detail=fact.detail, tool=fact.tool, subject=subject)


def ev(source: str, *lines: str, limit: int = 8) -> Evidence:
    return Evidence(source, tuple(line for line in lines if line)[:limit])
