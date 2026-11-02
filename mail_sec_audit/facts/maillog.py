"""One pass over mail logs feeding Postfix statistics and mail auth counters,
and one pass over SSH logs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..host import Host
from ..logs.auth import AuthCounter
from ..logs.sources import ReadStats, read
from ..logs.stats import MailStats
from ..model import Completeness
from ..runner import Runner
from ..stacks.base import LogSource, Stack

SSH_FILES = LogSource("files", patterns=("/var/log/auth.log*", "/var/log/secure*"))
SSH_JOURNAL = LogSource("journal", units=("ssh.service", "sshd.service"))


@dataclass(frozen=True)
class LogResult:
    read: ReadStats
    auth: AuthCounter
    statistics: Optional[dict[str, Any]]


def mail(
    host: Host, runner: Runner, stack: Stack, start: Any, end: Any, top: int, completeness: Completeness
) -> LogResult:
    stats = ReadStats()
    counter = AuthCounter()
    collector = MailStats() if stack.mta == "postfix" else None
    for when, header in read(host, runner, stack.mail_logs, start, end, completeness, stats):
        counter.feed_mail(header)
        if collector is not None:
            collector.feed(when, header)
    statistics = None
    if collector is not None and stats.in_period:
        statistics = collector.result(top)
        statistics["period"] = {
            "requested_from": start.isoformat(sep=" ", timespec="seconds"),
            "requested_to": end.isoformat(sep=" ", timespec="seconds"),
            "observed_from": stats.first.isoformat(sep=" ", timespec="seconds") if stats.first else None,
            "observed_to": stats.last.isoformat(sep=" ", timespec="seconds") if stats.last else None,
        }
        statistics["source"] = {
            "lines_scanned": stats.scanned,
            "timestamped_lines": stats.timestamped,
            "lines_in_period": stats.in_period,
        }
    return LogResult(stats, counter, statistics)


def ssh(host: Host, runner: Runner, start: Any, end: Any, completeness: Completeness) -> LogResult:
    stats = ReadStats()
    counter = AuthCounter()
    # The journal first (current systemd hosts); files when it yields nothing.
    sources = [SSH_JOURNAL, SSH_FILES] if host.is_dir("/run/systemd/system") else [SSH_FILES]
    for source in sources:
        if source.kind == "files" and stats.scanned:
            continue
        for _when, header in read(host, runner, [source], start, end, completeness, stats):
            counter.feed_ssh(header)
    return LogResult(stats, counter, None)
