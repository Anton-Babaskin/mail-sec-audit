"""Orchestration: lock, signals, temporary directory, checks, output."""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import shutil
import signal
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from types import FrameType
from typing import Optional

from . import __version__, cli
from .facts import Facts
from .host import Host
from .i18n import Translator, select_language
from .model import Completeness, Report
from .render import fleetops, json_v1
from .render.redact import NO_REDACTION, Redactor
from .render.terminal import TextRenderer
from .rules import SECTIONS, run_checks
from .rules.base import Ctx
from .runner import Runner, SystemRunner
from .safefile import LockBusy, ReportError, ReportTarget, default_lock_path, open_report, single_instance

EX_USAGE = 64
EX_CANTCREAT = 73
EX_TEMPFAIL = 75


class Terminated(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


def _raise_terminated(signum: int, _frame: Optional[FrameType]) -> None:
    raise Terminated(signum)


@contextlib.contextmanager
def signal_guard() -> Iterator[None]:
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, _raise_terminated)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def local_users(host: Host) -> list[str]:
    read = host.read_text("/etc/passwd")
    users = []
    for line in read.text.splitlines() if read.ok else []:
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit() and 1000 <= int(parts[2]) < 65534:
            users.append(parts[0])
    return users


def build_report(
    config: cli.Config,
    host: Host,
    runner: Runner,
    t: Translator,
    tmpdir: str,
) -> tuple[Report, dict[str, int]]:
    started = host.now()
    clock = time.monotonic()
    completeness = Completeness()
    facts = Facts(host, runner, config, completeness)
    facts.tmpdir = tmpdir
    ctx = Ctx(config=config, host=host, facts=facts, completeness=completeness)
    stack = facts.stack()
    ctx.stack = stack
    findings = run_checks(ctx)
    identity = facts.identity()
    mail_host = config.mail_host or identity.fqdn
    platform = f"{stack.name} ({stack.version})" if stack.version else stack.name
    context = [
        ("ui.ctx.date", started.isoformat(timespec="seconds")),
        ("ui.ctx.host", identity.hostname),
        ("ui.ctx.mail_host", mail_host),
        ("ui.ctx.domain", config.mail_domain or t("ui.ctx.domain_none")),
        ("ui.ctx.platform", platform),
        ("ui.ctx.mta", f"{stack.mta} / {stack.imap}"),
        ("ui.ctx.period", f"{config.period_from:%Y-%m-%d %H:%M:%S} -> {config.period_to:%Y-%m-%d %H:%M:%S}"),
        ("ui.ctx.kernel", identity.kernel),
        ("ui.ctx.os", identity.os_name),
        ("ui.ctx.lang", t.lang),
    ]
    report = Report(
        tool_version=__version__,
        lang=t.lang,
        hostname=identity.hostname,
        host_id=identity.host_id,
        mail_host=mail_host,
        mail_domain=config.mail_domain,
        platform=stack.name,
        platform_version=stack.version,
        period_from=config.period_from,
        period_to=config.period_to,
        started_at=started,
        duration_ms=int((time.monotonic() - clock) * 1000),
        findings=findings,
        context=context,
        mail_statistics=ctx.extra.get("mail_statistics"),
        auth_statistics=ctx.extra.get("auth_statistics"),
        filesystems=ctx.extra.get("filesystems", []),
        completeness=completeness,
    )
    durations: dict[str, int] = ctx.extra.get("durations", {})
    return report, durations


def render(
    report: Report,
    config: cli.Config,
    t: Translator,
    redactor: Redactor,
    durations: Mapping[str, int],
    *,
    color: bool,
    width: int,
) -> tuple[str, str]:
    """Return (stdout text, report-file text)."""
    if config.output_format == "json":
        text = json_v1.render(report, t, redactor, redacted=config.redact)
        return text, text
    if config.output_format == "fleetops":
        text = fleetops.render(report, t, redactor, redacted=config.redact, durations=durations)
        return text, text
    plain = TextRenderer(t, redactor, color=False, verbose=config.verbose, width=width, sections=SECTIONS)
    screen = TextRenderer(t, redactor, color=color, verbose=config.verbose, width=width, sections=SECTIONS)
    return screen.render(report), plain.render(report)


def _width(env: Mapping[str, str]) -> int:
    value = env.get("COLUMNS", "")
    return int(value) if value.isdigit() and 60 <= int(value) <= 200 else 88


def run_audit(config: cli.Config, t: Translator, env: Mapping[str, str]) -> int:
    host = Host()
    runner = SystemRunner()
    target: Optional[ReportTarget] = None
    tmpdir = ""
    try:
        with signal_guard(), single_instance(default_lock_path(host.euid, dict(env))):
            if config.report_path:
                target = open_report(config.report_path, append=config.append_report, euid=host.euid)
            tmpdir = tempfile.mkdtemp(prefix="mail-sec-audit.")
            report, durations = build_report(config, host, runner, t, tmpdir)
            redactor = NO_REDACTION
            if config.redact:
                names = [report.hostname, report.mail_host, config.mail_domain or "", config.mail_host or ""]
                redactor = Redactor(names, local_users(host))
                if report.mail_statistics is not None:
                    report.mail_statistics = redact_statistics(report.mail_statistics, redactor)
            color = sys.stdout.isatty() and not config.no_color and "NO_COLOR" not in env
            screen, plain = render(report, config, t, redactor, durations, color=color, width=_width(env))
            sys.stdout.write(screen)
            sys.stdout.flush()
            if target is not None:
                target.write(plain)
                target.close()
                target = None
            if config.interactive:
                from .interactive import menu

                menu(config, host, runner, t, report)
            return report.exit_code
    except LockBusy as busy:
        sys.stderr.write(t("cli.error.prefix", {"message": t("cli.error.lock", {"path": busy.path})}) + "\n")
        return EX_TEMPFAIL
    except ReportError as error:
        sys.stderr.write(t("cli.error.prefix", {"message": t(error.key, error.params)}) + "\n")
        return EX_CANTCREAT
    except Terminated as stop:
        kill_all = getattr(runner, "kill_all", None)
        if callable(kill_all):
            kill_all()
        if target is not None:
            target.discard()
            target = None
        sys.stderr.write("\n" + t("signal.stopped", {"signal": signal.Signals(stop.signum).name}) + "\n")
        return 128 + stop.signum
    finally:
        if target is not None:
            target.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def redact_statistics(stats: dict[str, object], redactor: Redactor) -> dict[str, object]:
    """Replace mailbox and domain names in statistics with keyed pseudonyms."""
    result = dict(stats)
    for key, kind in (("top_users", "mailbox"), ("top_senders", "mailbox")):
        rows = result.get(key)
        if isinstance(rows, list):
            result[key] = [{**row, "address": redactor.pseudonym(kind, str(row.get("address", "")))} for row in rows]
    for key in ("top_sender_domains", "top_recipient_domains", "top_incoming_domains"):
        rows = result.get(key)
        if isinstance(rows, list):
            result[key] = [{**row, "domain": redactor.pseudonym("domain", str(row.get("domain", "")))} for row in rows]
    result["redacted"] = True
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = os.environ
    hint = cli.requested_language(args) or select_language(None, env)
    try:
        parsed = cli.parse(args, env, dt.datetime.now().astimezone())
    except cli.UsageError as error:
        t = Translator(hint)
        sys.stderr.write(t("cli.error.prefix", {"message": t(error.key, error.params)}) + "\n")
        if error.key == "cli.error.unknown_option":
            sys.stderr.write(t("cli.usage") + "\n")
        return EX_USAGE
    if isinstance(parsed, cli.Action):
        if parsed.name == "version":
            sys.stdout.write(f"mail-sec-audit {__version__}\n")
        else:
            sys.stdout.write(Translator(hint)("cli.usage") + "\n")
        return 0
    return run_audit(parsed, Translator(select_language(parsed.lang, env)), env)
