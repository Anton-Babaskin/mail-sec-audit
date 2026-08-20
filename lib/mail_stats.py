#!/usr/bin/env python3
"""Build deterministic Postfix traffic statistics from host or Docker logs."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SERVICE_RE = re.compile(r"(?P<service>postfix(?:/[\w-]+)+)\[\d+\]:\s*(?P<message>.*)$")
SYSLOG_DATE_RE = re.compile(r"(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
ISO_DATE_RE = re.compile(
    r"(?P<stamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
QUEUE_RE = re.compile(r"^(?P<qid>[A-Za-z0-9]{5,}):\s*(?P<body>.*)$")
ADDRESS_RE = re.compile(r"(?:from|to)=<([^>]*)>")
SASL_RE = re.compile(r"sasl_username=([^,\s]+)", re.IGNORECASE)
SIZE_RE = re.compile(r"\bsize=(\d+)")
STATUS_RE = re.compile(r"\bstatus=([a-z]+)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--from", dest="from_time", required=True)
    parser.add_argument("--to", dest="to_time", required=True)
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--redact", action="store_true")
    return parser.parse_args()


def parse_bound(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def parse_timestamp(line: str, now: dt.datetime) -> dt.datetime | None:
    iso = ISO_DATE_RE.search(line[:96])
    if iso:
        raw = iso.group("stamp").replace("Z", "+00:00")
        try:
            parsed = dt.datetime.fromisoformat(raw)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone().replace(tzinfo=None)
            return parsed
        except ValueError:
            pass

    syslog = SYSLOG_DATE_RE.search(line[:96])
    if not syslog:
        return None
    try:
        parsed = dt.datetime.strptime(f"{now.year} {syslog.group('stamp')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    if parsed > now + dt.timedelta(days=1):
        try:
            parsed = parsed.replace(year=now.year - 1)
        except ValueError:
            parsed = parsed.replace(year=now.year - 1, day=28)
    return parsed


def clean_address(value: str | None) -> str:
    return (value or "").strip().strip("<>").lower()


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1] if "@" in address else "(local/unknown)"


def pseudonym(kind: str, value: str) -> str:
    if value.startswith("("):
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{kind}-{digest}"


def new_message(timestamp: dt.datetime) -> dict[str, Any]:
    return {
        "first": timestamp,
        "last": timestamp,
        "sender": "",
        "user": "",
        "size": 0,
        "deliveries": [],
    }


def aggregate(messages: dict[str, dict[str, Any]], top: int, redact: bool) -> dict[str, Any]:
    users: dict[str, dict[str, Any]] = {}
    senders: dict[str, dict[str, Any]] = {}
    sender_domains: collections.Counter[str] = collections.Counter()
    recipient_domains: collections.Counter[str] = collections.Counter()
    incoming_domains: collections.Counter[str] = collections.Counter()
    status_counts: collections.Counter[str] = collections.Counter()
    totals = collections.Counter()

    def add_row(target: dict[str, dict[str, Any]], key: str, message: dict[str, Any], deliveries: int) -> None:
        row = target.setdefault(
            key,
            {"address": key, "submitted": 0, "messages": 0, "deliveries": 0, "bytes": 0, "first": None, "last": None},
        )
        row["messages"] += 1
        row["deliveries"] += deliveries
        row["bytes"] += message["size"]
        row["first"] = min(filter(None, (row["first"], message["first"])), default=message["first"])
        row["last"] = max(filter(None, (row["last"], message["last"])), default=message["last"])

    def add_submission(key: str, message: dict[str, Any]) -> None:
        row = users.setdefault(
            key,
            {"address": key, "submitted": 0, "messages": 0, "deliveries": 0, "bytes": 0, "first": None, "last": None},
        )
        row["submitted"] += 1
        row["first"] = min(filter(None, (row["first"], message["first"])), default=message["first"])
        row["last"] = max(filter(None, (row["last"], message["last"])), default=message["last"])

    for message in messages.values():
        if message["user"]:
            totals["authenticated_submissions"] += 1
            add_submission(message["user"], message)
        outbound_sent = [d for d in message["deliveries"] if d["transport"] == "smtp" and d["status"] == "sent"]
        local_sent = [
            d
            for d in message["deliveries"]
            if d["transport"] in {"lmtp", "local", "virtual", "pipe"} and d["status"] == "sent"
        ]
        for delivery in message["deliveries"]:
            status_counts[delivery["status"]] += 1
            if delivery["status"] == "bounced":
                totals["bounced_deliveries"] += 1
            elif delivery["status"] == "deferred":
                totals["deferred_deliveries"] += 1

        if outbound_sent:
            totals["outbound_messages"] += 1
            totals["outbound_deliveries"] += len(outbound_sent)
            totals["outbound_bytes"] += message["size"]
            sender = message["sender"] or "(unknown-sender)"
            user = message["user"]
            if user:
                totals["authenticated_outbound_messages"] += 1
                add_row(users, user, message, len(outbound_sent))
            add_row(senders, sender, message, len(outbound_sent))
            sender_domains[domain_of(sender)] += 1
            for delivery in outbound_sent:
                recipient_domains[domain_of(delivery["recipient"])] += 1

        if local_sent:
            totals["incoming_messages"] += 1
            totals["incoming_deliveries"] += len(local_sent)
            incoming_domains[domain_of(message["sender"] or "(unknown-sender)")] += 1

    totals["tracked_queue_ids"] = len(messages)

    def finish_rows(rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        result = sorted(
            rows.values(),
            key=lambda row: (-row["submitted"], -row["messages"], -row["deliveries"], row["address"]),
        )[:top]
        for row in result:
            row["first"] = row["first"].isoformat(sep=" ") if row["first"] else None
            row["last"] = row["last"].isoformat(sep=" ") if row["last"] else None
            if redact:
                row["address"] = pseudonym("mailbox", row["address"])
        return result

    def finish_domains(counter: collections.Counter[str]) -> list[dict[str, Any]]:
        rows = [{"domain": name, "count": count} for name, count in counter.most_common(top)]
        if redact:
            for row in rows:
                row["domain"] = pseudonym("domain", row["domain"])
        return rows

    return {
        "totals": dict(totals),
        "delivery_status": dict(sorted(status_counts.items())),
        "top_users": finish_rows(users),
        "top_senders": finish_rows(senders),
        "top_sender_domains": finish_domains(sender_domains),
        "top_recipient_domains": finish_domains(recipient_domains),
        "top_incoming_domains": finish_domains(incoming_domains),
    }


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\t".join(fields) + "\n")
        for row in rows:
            handle.write("\t".join(str(row.get(field, "")) for field in fields) + "\n")


def main() -> int:
    args = parse_args()
    start = parse_bound(args.from_time)
    end = parse_bound(args.to_time)
    now = dt.datetime.now().astimezone().replace(tzinfo=None)
    messages: dict[str, dict[str, Any]] = {}
    scanned = in_period = timestamped = 0
    observed_first: dt.datetime | None = None
    observed_last: dt.datetime | None = None

    with args.input.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            scanned += 1
            timestamp = parse_timestamp(raw_line, now)
            if timestamp is None:
                continue
            timestamped += 1
            if timestamp < start or timestamp > end:
                continue
            in_period += 1
            observed_first = min(filter(None, (observed_first, timestamp)), default=timestamp)
            observed_last = max(filter(None, (observed_last, timestamp)), default=timestamp)

            service_match = SERVICE_RE.search(raw_line)
            if not service_match:
                continue
            service = service_match.group("service")
            queue_match = QUEUE_RE.match(service_match.group("message"))
            if not queue_match:
                continue
            queue_id = queue_match.group("qid")
            body = queue_match.group("body")
            message = messages.setdefault(queue_id, new_message(timestamp))
            message["first"] = min(message["first"], timestamp)
            message["last"] = max(message["last"], timestamp)

            sasl = SASL_RE.search(body)
            if sasl:
                message["user"] = clean_address(sasl.group(1))

            if service.endswith("/qmgr") and "from=<" in body:
                address = ADDRESS_RE.search(body)
                if address:
                    message["sender"] = clean_address(address.group(1))
                size = SIZE_RE.search(body)
                if size:
                    message["size"] = int(size.group(1))

            transport = service.rsplit("/", 1)[-1]
            if transport in {"smtp", "lmtp", "local", "virtual", "pipe"}:
                address = ADDRESS_RE.search(body)
                status = STATUS_RE.search(body)
                if address and status:
                    message["deliveries"].append(
                        {
                            "transport": transport,
                            "recipient": clean_address(address.group(1)),
                            "status": status.group(1).lower(),
                            "timestamp": timestamp,
                        }
                    )

    result = aggregate(messages, args.top, args.redact)
    result["period"] = {
        "requested_from": start.isoformat(sep=" "),
        "requested_to": end.isoformat(sep=" "),
        "observed_from": observed_first.isoformat(sep=" ") if observed_first else None,
        "observed_to": observed_last.isoformat(sep=" ") if observed_last else None,
    }
    result["source"] = {
        "lines_scanned": scanned,
        "timestamped_lines": timestamped,
        "lines_in_period": in_period,
    }

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_tsv(args.output_dir / "top-users.tsv", result["top_users"], ["address", "submitted", "messages", "deliveries", "bytes", "first", "last"])
        write_tsv(args.output_dir / "top-senders.tsv", result["top_senders"], ["address", "submitted", "messages", "deliveries", "bytes", "first", "last"])
        for name in ("top_sender_domains", "top_recipient_domains", "top_incoming_domains"):
            write_tsv(args.output_dir / f"{name.replace('_', '-')}.tsv", result[name], ["domain", "count"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
