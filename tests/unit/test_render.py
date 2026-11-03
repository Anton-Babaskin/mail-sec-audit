from __future__ import annotations

import datetime as dt
import json
import unittest

from mail_sec_audit.i18n import Translator
from mail_sec_audit.model import Completeness, Evidence, Finding, Report, Status
from mail_sec_audit.render import fleetops, json_v1
from mail_sec_audit.render.redact import NO_REDACTION, Redactor
from mail_sec_audit.render.sanitize import clean
from mail_sec_audit.render.terminal import TextRenderer
from mail_sec_audit.rules import SECTIONS

# Field sets of HealthResult and CheckResult in Anton-Babaskin/FleetOps
# fleetops/domain/models.py (both declare extra="forbid").
FLEETOPS_HEALTH = {"schema_version", "host", "collected_at", "duration_ms", "overall_status", "checks"}
FLEETOPS_CHECK = {"name", "status", "summary", "metrics", "reason", "error", "timed_out", "duration_ms", "raw_ref"}
FLEETOPS_STATUS = {"ok", "warning", "critical", "unknown"}
V1_TOP = {
    "schema_version",
    "tool",
    "generated_at",
    "target",
    "period",
    "result",
    "findings",
    "mail_statistics",
    "filesystems",
}


def report(*findings: Finding) -> Report:
    when = dt.datetime(2026, 11, 2, 12, 0, tzinfo=dt.timezone.utc)
    return Report(
        tool_version="3.0.0",
        lang="en",
        hostname="mx1",
        host_id="0123456789abcdef",
        mail_host="mx1.example.org",
        mail_domain="example.org",
        platform="generic",
        platform_version=None,
        period_from=when - dt.timedelta(days=7),
        period_to=when,
        started_at=when,
        duration_ms=1234,
        findings=list(findings),
        completeness=Completeness(),
    )


WARN = Finding(
    "CTX.FQDN",
    Status.WARN,
    "ctx.fqdn.warn",
    {"name": "mx1"},
    evidence=(Evidence("cmd:hostname -f", ("mx1",)),),
    next_step="ctx.fqdn.next",
)
UNKNOWN = Finding(
    "CTX.PRIVILEGES",
    Status.UNKNOWN,
    "common.unknown.timeout",
    {"source": "sshd -T", "detail": "-", "tool": "sshd"},
    reason="timeout",
    next_step="common.next.unknown",
)
NA = Finding(
    "CTX.PRIVILEGES",
    Status.NA,
    "common.na.not_requested",
    {"detail": "no --domain"},
    reason="not_requested",
    subject="x",
)


class SanitizeTest(unittest.TestCase):
    def test_control_ansi_and_bidi_are_escaped(self) -> None:
        self.assertEqual(clean("a\x1b[31mb"), "a\\x1b[31mb")
        self.assertEqual(clean("a‮b"), "a\\u202eb")
        self.assertEqual(clean("a\nb\rc\x00"), "a\\x0ab\\x0dc\\x00")
        self.assertEqual(clean("tab\there"), "tab here")
        self.assertEqual(len(clean("x" * 500, 50)), 50)


class RedactTest(unittest.TestCase):
    def test_times_and_apt_keys_survive(self) -> None:
        r = Redactor(["mx1.example.org"], ["alice"])
        text = "2026-11-02T10:00:00+03:00 APT::Periodic::Update-Package-Lists 10:00:00"
        self.assertEqual(r(text), text)

    def test_identifiers_are_removed(self) -> None:
        r = Redactor(["mx1.example.org", "example.org", "mx1"], ["alice"])
        text = (
            "from alice@example.org at 203.0.113.9 and [2001:db8::1]:25 via mx1.example.org, "
            "imap.example.org, user alice home /home/alice; ::ffff:198.51.100.7"
        )
        out = r(text)
        for leaked in ("alice", "203.0.113.9", "2001:db8::1", "example.org", "198.51.100.7"):
            self.assertNotIn(leaked, out)
        self.assertIn("<redacted-email>", out)
        self.assertIn("<redacted-host>", out)

    def test_pseudonyms_are_keyed_per_run(self) -> None:
        a, b = Redactor(), Redactor()
        self.assertEqual(a.pseudonym("mailbox", "Bob@Example.org"), a.pseudonym("mailbox", "bob@example.org"))
        self.assertNotEqual(a.pseudonym("mailbox", "bob@example.org"), b.pseudonym("mailbox", "bob@example.org"))
        self.assertEqual(NO_REDACTION("bob@example.org"), "bob@example.org")


class JsonV1Test(unittest.TestCase):
    def test_v1_fields_and_mapping(self) -> None:
        data = json.loads(json_v1.render(report(WARN, UNKNOWN, NA), Translator("en"), NO_REDACTION, redacted=False))
        self.assertTrue(set(data) >= V1_TOP)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["result"]["status"], "review_required")
        self.assertEqual(data["result"]["exit_code"], 1)
        self.assertEqual(data["result"]["counts"], {"pass": 0, "info": 1, "warning": 2, "critical": 0})
        unknown = data["findings"][1]
        self.assertEqual((unknown["severity"], unknown["status"], unknown["reason"]), ("warning", "UNKNOWN", "timeout"))
        self.assertEqual(data["findings"][2]["id"], "CTX.PRIVILEGES@x")
        self.assertEqual(data["findings"][2]["severity"], "info")
        self.assertIsNone(data["findings"][2]["remediation"])
        self.assertEqual(data["period"]["to"], "2026-11-02 12:00:00")

    def test_redacted_target(self) -> None:
        data = json_v1.build(report(WARN), Translator("en"), Redactor(["mx1.example.org"]), redacted=True)
        self.assertEqual(data["target"]["host"], "<redacted-host>")
        self.assertEqual(data["target"]["domain"], "<redacted-domain>")


class FleetOpsTest(unittest.TestCase):
    def test_contract(self) -> None:
        doc = fleetops.build(
            report(WARN, UNKNOWN, NA), Translator("ru"), NO_REDACTION, redacted=False, durations={"CTX.FQDN": 5}
        )
        self.assertEqual(set(doc), FLEETOPS_HEALTH)
        self.assertEqual(doc["schema_version"], "1.0")
        self.assertEqual(set(doc["host"]), {"id", "hostname"})
        self.assertTrue(doc["host"]["id"] and doc["host"]["hostname"])
        dt.datetime.fromisoformat(doc["collected_at"])
        self.assertIsInstance(doc["duration_ms"], int)
        self.assertEqual(doc["overall_status"], "warning")
        for check in doc["checks"]:
            self.assertEqual(set(check), FLEETOPS_CHECK)
            self.assertIn(check["status"], FLEETOPS_STATUS)
            self.assertTrue(check["summary"])
            self.assertIsInstance(check["duration_ms"], int)
            self.assertGreaterEqual(check["duration_ms"], 0)
            self.assertIsInstance(check["metrics"], dict)
            self.assertIsInstance(check["timed_out"], bool)
        by_name = {c["name"]: c for c in doc["checks"]}
        self.assertEqual(by_name["CTX.PRIVILEGES"]["status"], "unknown")
        self.assertTrue(by_name["CTX.PRIVILEGES"]["timed_out"])
        self.assertEqual(by_name["CTX.FQDN"]["duration_ms"], 5)
        self.assertEqual(by_name["CTX.PRIVILEGES@x"]["metrics"]["native_status"], "N/A")

    def test_overall_unknown_ranks_below_warning(self) -> None:
        doc = fleetops.build(report(UNKNOWN), Translator("en"), NO_REDACTION, redacted=False, durations={})
        self.assertEqual(doc["overall_status"], "unknown")


class TerminalTest(unittest.TestCase):
    def test_text_has_no_ansi_without_color_and_shows_evidence(self) -> None:
        r = report(WARN)
        r.context = [("ui.ctx.host", "mx1\x1b[2J")]
        text = TextRenderer(Translator("en"), NO_REDACTION, color=False, verbose=False, sections=SECTIONS).render(r)
        self.assertNotIn("\x1b", text)
        self.assertIn("[ WARN ]", text)
        self.assertIn("source: cmd:hostname -f", text)
        self.assertIn("RESULT: REVIEW REQUIRED", text)
        colored = TextRenderer(Translator("ru"), NO_REDACTION, color=True, verbose=True, sections=SECTIONS).render(r)
        self.assertIn("\x1b[1;33m", colored)
        self.assertIn("ИТОГ", colored)

    def test_unknown_only_result_line(self) -> None:
        text = TextRenderer(Translator("en"), NO_REDACTION, color=False, verbose=False, sections=SECTIONS).render(
            report(UNKNOWN)
        )
        self.assertIn("RESULT: INCOMPLETE", text)


if __name__ == "__main__":
    unittest.main()
