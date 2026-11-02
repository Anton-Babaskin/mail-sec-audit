"""``--format fleetops``: FleetOps ``HealthResult`` (schema_version "1.0").

Field names and constraints follow ``fleetops/domain/models.py`` in
Anton-Babaskin/FleetOps: ``HealthResult`` and ``CheckResult`` forbid extra
fields, statuses are ok/warning/critical/unknown, ``summary`` is non-empty
and ``duration_ms`` is a non-negative integer. Details of each finding are
kept in ``metrics``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from ..i18n import Translator
from ..model import Report, Status
from .json_v1 import finding_dict

SCHEMA_VERSION = "1.0"
STATUS = {
    Status.OK: "ok",
    Status.INFO: "ok",
    Status.NA: "ok",
    Status.WARN: "warning",
    Status.FAIL: "critical",
    Status.UNKNOWN: "unknown",
}
PRIORITY = {"ok": 0, "unknown": 1, "warning": 2, "critical": 3}
HEALTH_FIELDS = ("schema_version", "host", "collected_at", "duration_ms", "overall_status", "checks")
CHECK_FIELDS = ("name", "status", "summary", "metrics", "reason", "error", "timed_out", "duration_ms", "raw_ref")


def _check(name: str, status: str, summary: str, metrics: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "summary": summary or name,
        "metrics": metrics,
        "reason": extra.get("reason"),
        "error": extra.get("error"),
        "timed_out": bool(extra.get("timed_out", False)),
        "duration_ms": max(0, int(extra.get("duration_ms", 0))),
        "raw_ref": None,
    }


def build(
    report: Report,
    t: Translator,
    redact: Callable[[str], str],
    *,
    redacted: bool,
    durations: Mapping[str, int],
) -> dict[str, Any]:
    checks = [
        _check(
            "CTX.AUDIT",
            "ok",
            f"mail-sec-audit {report.tool_version}",
            {
                "tool": "mail-sec-audit",
                "version": report.tool_version,
                "platform": report.platform,
                "platform_version": report.platform_version,
                "period_from": report.period_from.isoformat(),
                "period_to": report.period_to.isoformat(),
                "domain": ("<redacted-domain>" if redacted else report.mail_domain) if report.mail_domain else None,
                "completeness": [{"source": redact(s.source), "state": s.state} for s in report.completeness.sources],
                "local_probes": [redact(p) for p in report.completeness.local_probes],
                "external_probes": [redact(p) for p in report.completeness.external_probes],
            },
            duration_ms=0,
        )
    ]
    for finding in report.findings:
        data = finding_dict(finding, t, redact)
        error = data["message"] if finding.reason in ("command_failed", "internal_error") else None
        checks.append(
            _check(
                finding.id,
                STATUS[finding.status],
                data["message"],
                {
                    "native_status": finding.status.value,
                    "section": finding.section,
                    "source": data["source"],
                    "evidence": data["evidence"],
                    "next_step": data["next_step"],
                },
                reason=finding.reason,
                error=error,
                timed_out=finding.reason == "timeout",
                duration_ms=durations.get(finding.check_id, 0),
            )
        )
    if report.mail_statistics is not None:
        checks.append(_check("FLOW.STATISTICS", "ok", "Postfix statistics", dict(report.mail_statistics)))
    if report.filesystems:
        checks.append(_check("DISK.FILESYSTEMS", "ok", "filesystems", {"filesystems": report.filesystems}))
    overall = max((c["status"] for c in checks), key=lambda s: PRIORITY[s], default="unknown")
    return {
        "schema_version": SCHEMA_VERSION,
        "host": {"id": report.host_id, "hostname": "<redacted-host>" if redacted else report.mail_host},
        "collected_at": report.started_at.isoformat(),
        "duration_ms": max(0, report.duration_ms),
        "overall_status": overall,
        "checks": checks,
    }


def render(
    report: Report,
    t: Translator,
    redact: Callable[[str], str],
    *,
    redacted: bool,
    durations: Mapping[str, int],
) -> str:
    document = build(report, t, redact, redacted=redacted, durations=durations)
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
