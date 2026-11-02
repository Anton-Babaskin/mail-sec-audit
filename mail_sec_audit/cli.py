"""Command-line parsing. Keeps the 2.3 options, limits and exit code 64."""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional

PLATFORMS = ("auto", "generic", "mailcow", "iredmail", "mailinabox")
FORMATS = ("text", "json", "fleetops")
DNS_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
EX_USAGE = 64


class UsageError(Exception):
    def __init__(self, key: str, **params: Any) -> None:
        super().__init__(key)
        self.key = key
        self.params = params


@dataclass(frozen=True)
class Config:
    days: int
    mail_top: int
    period_from: dt.datetime
    period_to: dt.datetime
    mail_host: Optional[str]
    mail_domain: Optional[str]
    dkim_selector: Optional[str]
    platform: str
    output_format: str
    lang: Optional[str]
    redact: bool
    deep: bool
    report_path: Optional[str]
    append_report: bool
    interactive: bool
    verbose: bool
    no_color: bool
    allowed_ports: tuple[int, ...]

    @property
    def json_output(self) -> bool:
        return self.output_format in ("json", "fleetops")


@dataclass(frozen=True)
class Action:
    """--help or --version: print and exit 0."""

    name: str


def _value(args: Sequence[str], index: int) -> str:
    option = args[index]
    if index + 1 >= len(args) or not args[index + 1] or args[index + 1].startswith("-"):
        raise UsageError("cli.error.requires_value", option=option)
    return args[index + 1]


def _bounded_int(text: str, low: int, high: int, digits: int, key: str) -> int:
    if not text.isdigit() or len(text) > digits:
        raise UsageError(key)
    value = int(text, 10)
    if not low <= value <= high:
        raise UsageError(key)
    return value


def _date(option: str, text: str) -> dt.date:
    if not DATE_RE.fullmatch(text):
        raise UsageError("cli.error.date", option=option)
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        raise UsageError("cli.error.date", option=option) from None


def _dns(option: str, text: str) -> str:
    if len(text) > 253 or not DNS_RE.fullmatch(text):
        raise UsageError("cli.error.dns_name", option=option, value=text)
    return text


def parse_ports(text: str) -> tuple[int, ...]:
    ports = []
    for token in text.split():
        if not token.isdigit() or len(token) > 5 or not 1 <= int(token, 10) <= 65535:
            raise UsageError("cli.error.ports", value=token)
        ports.append(int(token, 10))
    return tuple(ports)


def compute_period(
    days: int, date_from: Optional[dt.date], date_to: Optional[dt.date], now: dt.datetime
) -> tuple[dt.datetime, dt.datetime, int]:
    """Same semantics as 2.3: inclusive local calendar days."""
    local_now = now.astimezone().replace(microsecond=0)
    tz = local_now.tzinfo

    def at(day: dt.date, hour: int, minute: int, second: int) -> dt.datetime:
        return dt.datetime(day.year, day.month, day.day, hour, minute, second).astimezone(tz)

    end = at(date_to, 23, 59, 59) if date_to else local_now
    if date_from:
        start = at(date_from, 0, 0, 0)
    elif date_to:
        start = at(date_to - dt.timedelta(days=days - 1), 0, 0, 0)
    else:
        start = at((local_now - dt.timedelta(days=days)).date(), 0, 0, 0)
    if start > end:
        raise UsageError("cli.error.period")
    span = int((end - start).total_seconds())
    return start, end, max(1, (span + 86399) // 86400)


def requested_language(args: Sequence[str]) -> Optional[str]:
    for index, arg in enumerate(args[:-1]):
        if arg == "--lang" and args[index + 1] in ("ru", "en"):
            return args[index + 1]
    return None


def parse(args: Sequence[str], env: Mapping[str, str], now: dt.datetime) -> Config | Action:
    days = 7
    mail_top = 20
    date_from: Optional[dt.date] = None
    date_to: Optional[dt.date] = None
    options: dict[str, Any] = {
        "mail_host": None,
        "mail_domain": None,
        "dkim_selector": None,
        "platform": "auto",
        "output_format": "text",
        "lang": None,
        "redact": False,
        "deep": False,
        "report_path": None,
        "append_report": False,
        "interactive": False,
        "verbose": False,
        "no_color": False,
    }
    flags = {
        "--redact": "redact",
        "--deep": "deep",
        "--interactive": "interactive",
        "--manage-bans": "interactive",
        "--verbose": "verbose",
        "--no-color": "no_color",
    }
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-h", "--help"):
            return Action("help")
        if arg == "--version":
            return Action("version")
        if arg in flags:
            options[flags[arg]] = True
            index += 1
            continue
        if arg not in (
            "--days",
            "--mail-top",
            "--from",
            "--to",
            "--hostname",
            "--domain",
            "--dkim-selector",
            "--platform",
            "--format",
            "--lang",
            "--report",
            "--append-report",
        ):
            raise UsageError("cli.error.unknown_option", option=arg)
        value = _value(args, index)
        if arg == "--days":
            days = _bounded_int(value, 1, 3650, 4, "cli.error.days")
        elif arg == "--mail-top":
            mail_top = _bounded_int(value, 1, 100, 3, "cli.error.mail_top")
        elif arg == "--from":
            date_from = _date(arg, value)
        elif arg == "--to":
            date_to = _date(arg, value)
        elif arg == "--hostname":
            options["mail_host"] = _dns(arg, value)
        elif arg == "--domain":
            options["mail_domain"] = _dns(arg, value)
        elif arg == "--dkim-selector":
            options["dkim_selector"] = _dns(arg, value)
        elif arg == "--platform":
            if value not in PLATFORMS:
                raise UsageError("cli.error.platform", value=value)
            options["platform"] = value
        elif arg == "--format":
            if value not in FORMATS:
                raise UsageError("cli.error.format")
            options["output_format"] = value
        elif arg == "--lang":
            if value not in ("ru", "en"):
                raise UsageError("cli.error.lang")
            options["lang"] = value
        else:
            if options["report_path"] is not None:
                raise UsageError("cli.error.report_once")
            options["report_path"] = value
            options["append_report"] = arg == "--append-report"
        index += 2

    allowed_ports = parse_ports(env.get("MAIL_AUDIT_ALLOWED_PORTS", ""))
    json_output = options["output_format"] in ("json", "fleetops")
    if json_output and options["append_report"]:
        raise UsageError("cli.error.json_append")
    if json_output and options["interactive"]:
        raise UsageError("cli.error.json_interactive")
    period_from, period_to, days = compute_period(days, date_from, date_to, now)
    return Config(
        days=days,
        mail_top=mail_top,
        period_from=period_from,
        period_to=period_to,
        allowed_ports=allowed_ports,
        **options,
    )
