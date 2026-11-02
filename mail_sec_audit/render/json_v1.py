"""``--format json``: schema_version 1, kept compatible with 2.3.

All 2.3 fields keep their names and value sets. New fields are additive:
``findings[].status/section/subject/source/evidence/next_step/reason`` and
``duration_ms``, ``lang``, ``status_counts``, ``auth_statistics``,
``completeness`` at the top level. UNKNOWN maps to severity ``warning`` and
N/A to ``info``; the exact status is in ``status``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ..i18n import Translator
from ..model import Finding, Report, Status
from .sanitize import clean

SEVERITY = {
    Status.OK: "pass",
    Status.INFO: "info",
    Status.WARN: "warning",
    Status.FAIL: "critical",
    Status.UNKNOWN: "warning",
    Status.NA: "info",
}
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def finding_dict(f: Finding, t: Translator, redact: Callable[[str], str]) -> dict[str, Any]:
    next_step = redact(t(f.next_step)) if f.next_step else None
    severity = SEVERITY[f.status]
    return {
        "id": f.id,
        "severity": severity,
        "message": redact(t(f.key, f.params)),
        "remediation": next_step if severity in ("warning", "critical") else None,
        "status": f.status.value,
        "section": f.section,
        "check": f.check_id,
        "subject": redact(f.subject) if f.subject else None,
        "source": redact(f.source) if f.source else None,
        "evidence": [
            {"source": redact(e.source), "excerpt": [redact(clean(line, 400)) for line in e.excerpt]}
            for e in f.evidence
        ],
        "next_step": next_step,
        "reason": f.reason,
    }


def build(report: Report, t: Translator, redact: Callable[[str], str], *, redacted: bool) -> dict[str, Any]:
    counts = {"pass": 0, "info": 0, "warning": 0, "critical": 0}
    for finding in report.findings:
        counts[SEVERITY[finding.status]] += 1
    code = report.exit_code
    status = "critical" if code == 2 else "review_required" if code == 1 else "clean"
    return {
        "schema_version": 1,
        "tool": {"name": "mail-sec-audit", "version": report.tool_version},
        "generated_at": report.started_at.isoformat(),
        "target": {
            "host": "<redacted-host>" if redacted else report.mail_host,
            "domain": ("<redacted-domain>" if redacted else report.mail_domain) if report.mail_domain else None,
            "platform": report.platform,
            "platform_version": report.platform_version or None,
        },
        "period": {"from": report.period_from.strftime(TIME_FORMAT), "to": report.period_to.strftime(TIME_FORMAT)},
        "result": {"status": status, "exit_code": code, "counts": counts},
        "findings": [finding_dict(f, t, redact) for f in report.findings],
        "mail_statistics": report.mail_statistics,
        "filesystems": report.filesystems,
        "duration_ms": report.duration_ms,
        "lang": report.lang,
        "status_counts": {s.value: n for s, n in report.counts().items()},
        "auth_statistics": report.auth_statistics,
        "completeness": {
            "sources": [
                {"source": redact(s.source), "state": s.state, "detail": redact(s.detail)}
                for s in report.completeness.sources
            ],
            "local_probes": [redact(p) for p in report.completeness.local_probes],
            "external_probes": [redact(p) for p in report.completeness.external_probes],
        },
    }


def render(report: Report, t: Translator, redact: Callable[[str], str], *, redacted: bool) -> str:
    return json.dumps(build(report, t, redact, redacted=redacted), ensure_ascii=False, indent=2) + "\n"
