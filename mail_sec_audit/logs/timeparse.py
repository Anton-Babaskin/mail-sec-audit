"""Timestamps at the start of a log line.

Accepted forms, always anchored at the start of the line:
- ``docker logs --timestamps`` prefix (RFC 3339 UTC with up to 9 fraction digits),
  optionally followed by the container's own syslog header;
- RFC 3339 / ISO 8601 (rsyslog high precision, ``journalctl -o short-iso-precise``),
  with ``+HH:MM`` or ``+HHMM`` offsets;
- traditional syslog ``Mmm dd HH:MM:SS`` without a year. The year is chosen
  so that the time is not later than ``anchor`` (the file's mtime) plus one
  day, which handles year rollover and old rotated files.

A timestamp inside a message never counts: hostile ``helo=`` or subject
values cannot place a line into the period.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Optional

ISO_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,9}))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?\s+"
)
SYSLOG_RE = re.compile(r"(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})\s+")
MONTHS = {
    m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)
}


def _iso(match: re.Match[str], default_tz: dt.tzinfo) -> Optional[dt.datetime]:
    frac = (match.group("frac") or "")[:6].ljust(6, "0")
    tz = match.group("tz")
    try:
        value = dt.datetime.strptime(f"{match.group('date')} {match.group('time')}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    value = value.replace(microsecond=int(frac))
    if tz is None:
        return value.replace(tzinfo=default_tz)
    if tz == "Z":
        return value.replace(tzinfo=dt.timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    offset = dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return value.replace(tzinfo=dt.timezone(sign * offset))


def _syslog(match: re.Match[str], anchor: dt.datetime) -> Optional[dt.datetime]:
    month = MONTHS.get(match.group("mon"))
    if month is None:
        return None
    hour, minute, second = (int(x) for x in match.group("time").split(":"))
    local_anchor = anchor.astimezone()
    for year in (local_anchor.year, local_anchor.year - 1):
        try:
            naive = dt.datetime(year, month, int(match.group("day")), hour, minute, second)
        except ValueError:
            continue  # 29 Feb in a non-leap year
        value = naive.astimezone()
        if value <= local_anchor + dt.timedelta(days=1):
            return value
    return None


def split_time(line: str, anchor: dt.datetime) -> Optional[tuple[dt.datetime, str]]:
    """Return (timestamp, rest of line) or None when the line has no leading timestamp."""
    local_tz = anchor.astimezone().tzinfo or dt.timezone.utc
    match = ISO_RE.match(line)
    if match:
        stamp = _iso(match, local_tz)
        if stamp is None:
            return None
        rest = line[match.end() :]
        # docker logs --timestamps wraps the container's own line, which may
        # carry its own syslog or ISO header; the Docker time (UTC) wins.
        inner = ISO_RE.match(rest) or SYSLOG_RE.match(rest)
        if inner:
            rest = rest[inner.end() :]
        return stamp, rest
    match = SYSLOG_RE.match(line)
    if match:
        stamp = _syslog(match, anchor)
        return (stamp, line[match.end() :]) if stamp else None
    return None
