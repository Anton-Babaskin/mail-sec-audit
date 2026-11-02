"""Local signs of backup tooling and jobs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..host import Host
from ..runner import Runner

BACKUP_TOOLS = ("restic", "borg", "borgmatic", "rclone", "duplicity", "rsnapshot", "bacula-fd", "urbackupclientctl")
BACKUP_RE = re.compile(r"restic|borgmatic|\bborg\b|rclone|duplicity|rsnapshot|bacula|urbackup|backup", re.IGNORECASE)
JOB_DIRS = (
    "/etc/systemd/system",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)


@dataclass(frozen=True)
class BackupIndicators:
    tools: tuple[str, ...]
    jobs: tuple[str, ...]
    hints: tuple[str, ...]


def collect(host: Host, runner: Runner, hints: tuple[str, ...]) -> BackupIndicators:
    tools = tuple(t for t in BACKUP_TOOLS if runner.which(t))
    jobs: list[str] = []
    for directory in JOB_DIRS:
        for name in host.listdir(directory) or []:
            path = f"{directory}/{name}"
            if not host.is_regular(path):
                continue
            read = host.read_text(path, 128 * 1024)
            if BACKUP_RE.search(name) or (read.ok and BACKUP_RE.search(read.text)):
                jobs.append(path)
    found_hints = tuple(h for h in hints if host.exists(h))
    return BackupIndicators(tools, tuple(jobs), found_hints)
