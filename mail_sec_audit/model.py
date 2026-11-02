"""Result model: statuses, findings, evidence, completeness and the report."""

from __future__ import annotations

import datetime as dt
import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional


class Status(str, enum.Enum):
    OK = "OK"
    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NA = "N/A"


class Reason:
    """Machine-readable reasons for UNKNOWN and N/A."""

    MISSING_TOOL = "missing_tool"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    TRUNCATED = "truncated"
    NO_DATA = "no_data"
    COMMAND_FAILED = "command_failed"
    PARSE_ERROR = "parse_error"
    INTERNAL_ERROR = "internal_error"
    NOT_APPLICABLE = "not_applicable"
    NOT_REQUESTED = "not_requested"

    UNKNOWN_REASONS = frozenset(
        {MISSING_TOOL, PERMISSION_DENIED, TIMEOUT, TRUNCATED, NO_DATA, COMMAND_FAILED, PARSE_ERROR, INTERNAL_ERROR}
    )
    NA_REASONS = frozenset({NOT_APPLICABLE, NOT_REQUESTED})


@dataclass(frozen=True)
class Evidence:
    """Where a finding comes from and a short excerpt of the raw data.

    ``source`` is ``cmd:<argv>``, ``file:<path>``, ``log:<source>``,
    ``dns:<type> <name>``, ``tls:<address>`` or ``proc:<path>``. Excerpts are
    untrusted and are sanitized by the renderers.
    """

    source: str
    excerpt: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    check_id: str
    status: Status
    key: str
    params: Mapping[str, Any] = field(default_factory=dict)
    subject: Optional[str] = None
    evidence: tuple[Evidence, ...] = ()
    next_step: Optional[str] = None
    reason: Optional[str] = None

    @property
    def id(self) -> str:
        return f"{self.check_id}@{self.subject}" if self.subject else self.check_id

    @property
    def section(self) -> str:
        return self.check_id.split(".", 1)[0]

    @property
    def source(self) -> Optional[str]:
        return self.evidence[0].source if self.evidence else None


@dataclass(frozen=True)
class SourceState:
    source: str
    state: str
    detail: str = ""


@dataclass
class Completeness:
    sources: list[SourceState] = field(default_factory=list)
    local_probes: list[str] = field(default_factory=list)
    external_probes: list[str] = field(default_factory=list)

    def add_source(self, source: str, state: str, detail: str = "") -> None:
        entry = SourceState(source, state, detail)
        if entry not in self.sources:
            self.sources.append(entry)


@dataclass
class Report:
    tool_version: str
    lang: str
    hostname: str
    host_id: str
    mail_host: str
    mail_domain: Optional[str]
    platform: str
    platform_version: Optional[str]
    period_from: dt.datetime
    period_to: dt.datetime
    started_at: dt.datetime
    duration_ms: int
    findings: list[Finding]
    context: list[tuple[str, str]] = field(default_factory=list)
    mail_statistics: Optional[dict[str, Any]] = None
    auth_statistics: Optional[dict[str, Any]] = None
    filesystems: list[dict[str, Any]] = field(default_factory=list)
    completeness: Completeness = field(default_factory=Completeness)

    def counts(self) -> dict[Status, int]:
        counts = {status: 0 for status in Status}
        for finding in self.findings:
            counts[finding.status] += 1
        return counts

    @property
    def exit_code(self) -> int:
        return exit_code_for(f.status for f in self.findings)


def exit_code_for(statuses: Any) -> int:
    """0 clean, 1 WARN or UNKNOWN, 2 FAIL."""
    seen = set(statuses)
    if Status.FAIL in seen:
        return 2
    if Status.WARN in seen or Status.UNKNOWN in seen:
        return 1
    return 0
