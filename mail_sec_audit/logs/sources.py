"""Read log lines for the audit period from files, journald or Docker.

Files are read oldest first, rotated ``.gz`` files are streamed, and files
whose mtime is before the period are skipped (no line in a file is newer
than its mtime). Every source is recorded in completeness with its state.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from ..host import Host
from ..model import Completeness
from ..runner import ExecState, Runner
from ..stacks.base import LogSource
from .lines import Header, parse_header
from .timeparse import split_time

JOURNAL_TIME = "%Y-%m-%d %H:%M:%S"


@dataclass
class ReadStats:
    scanned: int = 0
    timestamped: int = 0
    in_period: int = 0
    first: dt.datetime | None = None
    last: dt.datetime | None = None
    readable_sources: int = 0
    failed_sources: list[tuple[str, str]] = field(default_factory=list)

    def seen(self, when: dt.datetime) -> None:
        self.in_period += 1
        self.first = when if self.first is None else min(self.first, when)
        self.last = when if self.last is None else max(self.last, when)


def _record(completeness: Completeness, stats: ReadStats, source: str, state: str, detail: str = "") -> None:
    completeness.add_source(source, state, detail)
    if state in ("ok", "empty"):
        stats.readable_sources += 1
    else:
        stats.failed_sources.append((source, state))


def _emit(
    lines: Iterator[str], anchor: dt.datetime, start: dt.datetime, end: dt.datetime, stats: ReadStats
) -> Iterator[tuple[dt.datetime, Header]]:
    for line in lines:
        stats.scanned += 1
        parsed = split_time(line, anchor)
        if parsed is None:
            continue
        stats.timestamped += 1
        when, rest = parsed
        if when < start or when > end:
            continue
        header = parse_header(rest)
        if header is None:
            continue
        stats.seen(when)
        yield when, header


def read(
    host: Host,
    runner: Runner,
    sources: Sequence[LogSource],
    start: dt.datetime,
    end: dt.datetime,
    completeness: Completeness,
    stats: ReadStats,
) -> Iterator[tuple[dt.datetime, Header]]:
    """Yield (time, header) for lines in [start, end].

    A ``journal`` source is a fallback: it is read only when the file
    sources before it produced no line.
    """
    for source in sources:
        if source.kind == "journal" and stats.scanned:
            continue
        if source.kind == "files":
            yield from _files(host, source, start, end, completeness, stats)
        elif source.kind == "journal":
            if not host.is_dir("/run/systemd/system") or not source.units:
                continue
            argv = ["journalctl", "--no-pager", "-q", "-o", "short-iso-precise"]
            argv += [
                "--since",
                start.astimezone().strftime(JOURNAL_TIME),
                "--until",
                end.astimezone().strftime(JOURNAL_TIME),
            ]
            for unit in source.units:
                argv += ["-u", unit]
            yield from _stream(runner, argv, f"journal:{','.join(source.units)}", host, start, end, completeness, stats)
        elif source.kind == "docker" and source.container:
            argv = ["docker", "logs", "--timestamps", "--since", str(int(start.timestamp()))]
            argv += ["--until", str(int(end.timestamp()) + 1), source.container]
            yield from _stream(runner, argv, f"docker:{source.container[:12]}", host, start, end, completeness, stats)


def _files(
    host: Host,
    source: LogSource,
    start: dt.datetime,
    end: dt.datetime,
    completeness: Completeness,
    stats: ReadStats,
) -> Iterator[tuple[dt.datetime, Header]]:
    paths: list[tuple[float, str]] = []
    for pattern in source.patterns:
        for path in host.glob(pattern):
            info = host.stat(path)
            if info is None:
                if host.exists(path):
                    _record(completeness, stats, f"log:{path}", "denied")
                continue
            if info.st_mtime < start.timestamp():
                continue
            paths.append((info.st_mtime, path))
    for mtime, path in sorted(set(paths)):
        anchor = dt.datetime.fromtimestamp(mtime, dt.timezone.utc)
        try:
            with host.open_lines(path) as lines:
                before = stats.scanned
                yield from _emit(lines, anchor, start, end, stats)
                _record(completeness, stats, f"log:{path}", "ok" if stats.scanned > before else "empty")
        except PermissionError:
            _record(completeness, stats, f"log:{path}", "denied")
        except (OSError, EOFError) as exc:
            _record(completeness, stats, f"log:{path}", "error", type(exc).__name__)


def _stream(
    runner: Runner,
    argv: list[str],
    label: str,
    host: Host,
    start: dt.datetime,
    end: dt.datetime,
    completeness: Completeness,
    stats: ReadStats,
) -> Iterator[tuple[dt.datetime, Header]]:
    before = stats.scanned
    with runner.stream(argv) as handle:
        yield from _emit(handle.lines, host.now(), start, end, stats)
    state = {
        ExecState.OK: "ok" if stats.scanned > before else "empty",
        ExecState.MISSING: "missing",
        ExecState.TIMEOUT: "timeout",
        ExecState.TRUNCATED: "truncated",
    }.get(handle.result.state, "error")
    if state == "error" and "permission" in handle.result.stderr.lower():
        state = "denied"
    _record(completeness, stats, label, state)
