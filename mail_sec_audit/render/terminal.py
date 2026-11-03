"""Human-readable report for the terminal and text report files."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from ..i18n import Translator
from ..model import Finding, Report, Status
from .sanitize import clean

COLORS = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[1;31m",
    "yellow": "\033[1;33m",
    "green": "\033[1;32m",
    "blue": "\033[1;34m",
    "cyan": "\033[1;36m",
    "magenta": "\033[1;35m",
    "reset": "\033[0m",
}
STATUS_COLOR = {
    Status.OK: "green",
    Status.INFO: "blue",
    Status.WARN: "yellow",
    Status.FAIL: "red",
    Status.UNKNOWN: "magenta",
    Status.NA: "dim",
}
DETAIL_STATUSES = (Status.WARN, Status.FAIL, Status.UNKNOWN)


class TextRenderer:
    def __init__(
        self,
        t: Translator,
        redact: Callable[[str], str],
        *,
        color: bool,
        verbose: bool,
        width: int = 88,
        sections: Sequence[str] = (),
    ) -> None:
        self.t = t
        self.redact = redact
        self.color = color
        self.verbose = verbose
        self.width = width
        self.sections = sections
        self.lines: list[str] = []

    def c(self, name: str, text: str) -> str:
        return f"{COLORS[name]}{text}{COLORS['reset']}" if self.color else text

    def safe(self, text: str, limit: int = 300) -> str:
        return clean(self.redact(text), limit)

    def out(self, text: str = "") -> None:
        self.lines.append(text)

    def hr(self) -> None:
        self.out(self.c("dim", "─" * self.width))

    def kv(self, label: str, value: str) -> None:
        self.out(f"  {self.c('dim', f'{label:<24}')} {self.safe(value)}")

    def render(self, report: Report) -> str:
        self.lines = []
        self.out()
        self.hr()
        self.out(self.c("bold", f"  {self.t('ui.title')}  v{report.tool_version}"))
        period = f"{report.period_from:%Y-%m-%d} -> {report.period_to:%Y-%m-%d}"
        host = self.safe(report.mail_host, 40)
        self.out(f"  {self.t('ui.banner.host')}: {host:<40} {self.t('ui.banner.period')}: {period}")
        self.hr()
        by_section: dict[str, list[Finding]] = {}
        for finding in report.findings:
            by_section.setdefault(finding.section, []).append(finding)
        number = 0
        for section in self.sections:
            items = by_section.get(section, [])
            if not items and section != "CTX":
                continue
            number += 1
            self.section(number, section)
            if section == "CTX":
                for label, value in report.context:
                    self.kv(self.t(label), value)
            for finding in items:
                self.finding(finding)
            if section == "AUTH" and report.auth_statistics:
                self.auth_tables(report.auth_statistics)
            if section == "FLOW" and report.mail_statistics:
                self.mail_tables(report.mail_statistics)
        self.summary(report, number + 1)
        return "\n".join(self.lines) + "\n"

    def section(self, number: int, code: str) -> None:
        self.out()
        self.out(self.c("cyan", f"[{number:02d}] {self.t('section.' + code)}"))
        self.hr()

    def finding(self, finding: Finding) -> None:
        label = self.t(f"ui.status.{finding.status.value}")
        message = self.safe(self.t(finding.key, finding.params), 400)
        self.out(f"{self.c(STATUS_COLOR[finding.status], f'[{label}]')} {message}")
        if not (self.verbose or finding.status in DETAIL_STATUSES):
            return
        for evidence in finding.evidence[:3]:
            self.out(f"         {self.c('dim', self.t('ui.evidence') + ':')} {self.safe(evidence.source, 200)}")
            for line in evidence.excerpt[: 8 if self.verbose else 3]:
                self.out(f"           {self.c('dim', '|')} {self.safe(line, 160)}")
        if finding.next_step and finding.status in DETAIL_STATUSES:
            self.out(f"         {self.c('dim', self.t('ui.next') + ':')} {self.safe(self.t(finding.next_step), 300)}")

    def ip_table(self, title: str, rows: Sequence[Sequence[Any]]) -> None:
        self.out(self.c("bold", title))
        rank = self.t("ui.table.rank")
        events = self.t("ui.table.events")
        source = self.t("ui.table.source_ip")
        self.out(f"  {self.c('dim', f'{rank:<4} {events:<9} {source}')}")
        if not rows:
            self.out(f"  {self.c('dim', self.t('ui.no_data'))}")
        for index, (ip, count) in enumerate(rows[:10], 1):
            color = "red" if count >= 200 else "yellow" if count >= 50 else "reset"
            self.out(self.c(color, f"  {index:<4} {count:<9} {self.safe(str(ip), 39)}"))

    def auth_tables(self, stats: dict[str, Any]) -> None:
        for key, title_key in (
            ("ssh_failed", "auth.table.ssh_failed"),
            ("ssh_accepted", "auth.table.ssh_accepted"),
            ("mail_failed", "auth.table.mail_failed"),
        ):
            if key in stats:
                self.ip_table(self.t(title_key), stats[key])

    def mail_tables(self, stats: dict[str, Any]) -> None:
        totals = stats.get("totals", {})
        period = stats.get("period", {})
        source = stats.get("source", {})
        self.kv(
            self.t("flow.kv.observed"),
            f"{period.get('observed_from') or '-'} -> {period.get('observed_to') or '-'}",
        )
        self.kv(
            self.t("flow.kv.lines"),
            self.t(
                "flow.kv.lines_value",
                {"period": source.get("lines_in_period", 0), "scanned": source.get("lines_scanned", 0)},
            ),
        )
        for name in (
            "outbound_messages",
            "outbound_deliveries",
            "authenticated_submissions",
            "authenticated_outbound_messages",
            "incoming_messages",
            "incoming_deliveries",
            "bounced_deliveries",
            "deferred_deliveries",
            "internal_hops",
            "outbound_bytes",
        ):
            self.kv(self.t(f"flow.total.{name}"), str(totals.get(name, 0)))
        for key, title_key in (("top_users", "flow.table.users"), ("top_senders", "flow.table.senders")):
            self.mailbox_table(self.t(title_key), stats.get(key, []))
        for key, title_key in (
            ("top_sender_domains", "flow.table.sender_domains"),
            ("top_recipient_domains", "flow.table.recipient_domains"),
            ("top_incoming_domains", "flow.table.incoming_domains"),
        ):
            self.domain_table(self.t(title_key), stats.get(key, []))

    def mailbox_table(self, title: str, rows: Sequence[dict[str, Any]]) -> None:
        self.out(self.c("bold", title))
        t = self.t
        header = (
            f"{t('ui.table.rank'):<4} {t('ui.table.mailbox'):<32} {t('ui.table.submitted'):>9} "
            f"{t('ui.table.delivered'):>9} {t('ui.table.recipients'):>10} {t('ui.table.bytes'):>12}"
        )
        self.out(f"  {self.c('dim', header)}")
        if not rows:
            self.out(f"  {self.c('dim', t('ui.no_data'))}")
        for index, row in enumerate(rows, 1):
            address = self.safe(str(row.get("address", "")), 32)
            self.out(
                f"  {index:<4} {address:<32.32} {row.get('submitted', 0):>9} {row.get('messages', 0):>9} "
                f"{row.get('deliveries', 0):>10} {row.get('bytes', 0):>12}"
            )

    def domain_table(self, title: str, rows: Sequence[dict[str, Any]]) -> None:
        self.out(self.c("bold", title))
        header = f"{self.t('ui.table.rank'):<4} {self.t('ui.table.domain'):<50} {self.t('ui.table.count'):>10}"
        self.out(f"  {self.c('dim', header)}")
        if not rows:
            self.out(f"  {self.c('dim', self.t('ui.no_data'))}")
        for index, row in enumerate(rows, 1):
            self.out(f"  {index:<4} {self.safe(str(row.get('domain', '')), 50):<50.50} {row.get('count', 0):>10}")

    def summary(self, report: Report, number: int) -> None:
        self.section(number, "SUMMARY")
        counts = report.counts()
        parts = []
        for status in Status:
            label = self.t(f"ui.status.{status.value}").strip()
            parts.append(self.c(STATUS_COLOR[status], f"{label:<7}") + f" {counts[status]:>4}")
        self.out("  " + "   ".join(parts))
        self.out()
        self.out(self.c("bold", f"  {self.t('ui.completeness')}:"))
        problems = [s for s in report.completeness.sources if s.state not in ("ok",)]
        if not problems:
            self.out(f"    {self.t('ui.completeness.none')}")
        for item in problems:
            detail = f" ({self.safe(item.detail, 120)})" if item.detail else ""
            self.out(f"    {self.safe(item.source, 120)}: {self.t('source.state.' + item.state)}{detail}")
        for label, probes in (
            ("ui.probes.local", report.completeness.local_probes),
            ("ui.probes.external", report.completeness.external_probes),
        ):
            value = ", ".join(self.safe(p, 80) for p in probes) if probes else self.t("ui.probes.none")
            self.out(f"  {self.t(label)}: {value}")
        self.out()
        if counts[Status.FAIL]:
            self.out(self.c("red", f"  {self.t('ui.result.critical')}"))
        elif counts[Status.WARN]:
            self.out(self.c("yellow", f"  {self.t('ui.result.review')}"))
        elif counts[Status.UNKNOWN]:
            self.out(self.c("magenta", f"  {self.t('ui.result.unknown')}"))
        else:
            self.out(self.c("green", f"  {self.t('ui.result.clean')}"))
