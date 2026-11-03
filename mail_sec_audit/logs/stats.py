"""Postfix traffic statistics, streamed and correlated by Queue ID.

Counted separately:
- messages: unique queue IDs with at least one successful delivery;
- deliveries: successful recipient deliveries;
- attempts: every delivery event, including ``deferred`` retries;
- internal hops: ``smtp`` to a loopback relay (content filters such as
  amavis on 127.0.0.1:10024) are not external deliveries. The original
  message's sender, size and SASL user carry over to the re-queued ID
  named in ``queued as ...`` so attribution survives the hop.

Local delivery is any ``lmtp``, ``local``, ``virtual`` or ``pipe`` delivery,
including LMTP to a loopback filter that delivers itself (spampd on
Mail-in-a-Box). Completed messages are folded into the totals when qmgr
logs ``removed``, so memory stays proportional to messages in flight.
"""

from __future__ import annotations

import collections
import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Optional

from .lines import Header
from .postfix import parse_client, parse_delivery, parse_expired, parse_qmgr, split_queue_id

LOCAL_TRANSPORTS = frozenset({"lmtp", "local", "virtual", "pipe"})
TOTAL_KEYS = (
    "outbound_messages",
    "authenticated_submissions",
    "authenticated_outbound_messages",
    "outbound_deliveries",
    "incoming_messages",
    "incoming_deliveries",
    "bounced_deliveries",
    "deferred_deliveries",
    "expired_messages",
    "internal_hops",
    "outbound_bytes",
    "tracked_queue_ids",
)


@dataclass
class Message:
    first: dt.datetime
    last: dt.datetime
    sender: str = ""
    user: str = ""
    size: int = 0
    outbound: list[str] = field(default_factory=list)
    local: int = 0
    hop: bool = False


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in address else "(local/unknown)"


class Row:
    def __init__(self, address: str) -> None:
        self.address = address
        self.submitted = 0
        self.messages = 0
        self.deliveries = 0
        self.bytes = 0
        self.first: Optional[dt.datetime] = None
        self.last: Optional[dt.datetime] = None

    def touch(self, message: Message) -> None:
        self.first = message.first if self.first is None else min(self.first, message.first)
        self.last = message.last if self.last is None else max(self.last, message.last)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "submitted": self.submitted,
            "messages": self.messages,
            "deliveries": self.deliveries,
            "bytes": self.bytes,
            "first": self.first.isoformat(sep=" ", timespec="seconds") if self.first else None,
            "last": self.last.isoformat(sep=" ", timespec="seconds") if self.last else None,
        }


class MailStats:
    def __init__(self) -> None:
        self.messages: dict[str, Message] = {}
        self.inherited: dict[str, tuple[str, str, int]] = {}
        self.totals: collections.Counter[str] = collections.Counter()
        self.status_counts: collections.Counter[str] = collections.Counter()
        self.users: dict[str, Row] = {}
        self.senders: dict[str, Row] = {}
        self.sender_domains: collections.Counter[str] = collections.Counter()
        self.recipient_domains: collections.Counter[str] = collections.Counter()
        self.incoming_domains: collections.Counter[str] = collections.Counter()
        self.seen_ids: set[str] = set()
        self.unparsed = 0

    def feed(self, when: dt.datetime, header: Header) -> None:
        process = header.postfix_process
        if process is None or header.watchdog:
            return
        split = split_queue_id(header.message)
        if split is None:
            return
        qid, body = split
        message = self.messages.get(qid)
        if message is None:
            message = Message(when, when)
            if qid in self.inherited:
                message.sender, message.user, message.size = self.inherited.pop(qid)
            self.messages[qid] = message
            self.seen_ids.add(qid)
        message.first = min(message.first, when)
        message.last = max(message.last, when)

        if process == "smtpd" and body.startswith("client="):
            client = parse_client(body)
            if client and client.sasl_user:
                message.user = client.sasl_user.strip().lower()
            elif client is None:
                self.unparsed += 1
        elif process == "qmgr":
            if body == "removed":
                self._finish(qid)
                return
            if body.startswith("from="):
                envelope = parse_qmgr(body)
                if envelope:
                    message.sender = envelope.sender.lower()
                    message.size = envelope.size
                elif parse_expired(body):
                    self.totals["expired_messages"] += 1
                else:
                    self.unparsed += 1
        elif process in ("smtp", "error", "discard", "retry") or process in LOCAL_TRANSPORTS:
            if not body.startswith("to="):
                return
            delivery = parse_delivery(body)
            if delivery is None:
                self.unparsed += 1
                return
            self.status_counts[delivery.status] += 1
            if delivery.status == "bounced":
                self.totals["bounced_deliveries"] += 1
            elif delivery.status == "deferred":
                self.totals["deferred_deliveries"] += 1
            if delivery.status != "sent":
                return
            if process == "smtp" and delivery.loopback:
                message.hop = True
                self.totals["internal_hops"] += 1
                if delivery.queued_as:
                    self.inherited[delivery.queued_as] = (message.sender, message.user, message.size)
            elif process == "smtp":
                message.outbound.append(delivery.recipient.lower())
            elif process in LOCAL_TRANSPORTS:
                message.local += 1

    def _finish(self, qid: str) -> None:
        message = self.messages.pop(qid, None)
        if message is None:
            return
        if (message.user and not message.hop) or (message.user and message.outbound):
            self.totals["authenticated_submissions"] += 1
            self._row(self.users, message.user).submitted += 1
            self._row(self.users, message.user).touch(message)
        if message.outbound:
            sender = message.sender or "(unknown-sender)"
            self.totals["outbound_messages"] += 1
            self.totals["outbound_deliveries"] += len(message.outbound)
            self.totals["outbound_bytes"] += message.size
            for table, key in ((self.senders, sender), (self.users, message.user)):
                if not key:
                    continue
                row = self._row(table, key)
                row.messages += 1
                row.deliveries += len(message.outbound)
                row.bytes += message.size
                row.touch(message)
            if message.user:
                self.totals["authenticated_outbound_messages"] += 1
            self.sender_domains[domain_of(sender)] += 1
            for recipient in message.outbound:
                self.recipient_domains[domain_of(recipient)] += 1
        if message.local:
            self.totals["incoming_messages"] += 1
            self.totals["incoming_deliveries"] += message.local
            self.incoming_domains[domain_of(message.sender or "(unknown-sender)")] += 1

    @staticmethod
    def _row(table: dict[str, Row], key: str) -> Row:
        if key not in table:
            table[key] = Row(key)
        return table[key]

    def result(self, top: int) -> dict[str, Any]:
        for qid in list(self.messages):
            self._finish(qid)
        self.totals["tracked_queue_ids"] = len(self.seen_ids)

        def rows(table: dict[str, Row]) -> list[dict[str, Any]]:
            ordered = sorted(table.values(), key=lambda r: (-r.submitted, -r.messages, -r.deliveries, r.address))
            return [r.as_dict() for r in ordered[:top]]

        def domains(counter: collections.Counter[str]) -> list[dict[str, Any]]:
            return [{"domain": d, "count": c} for d, c in sorted(counter.items(), key=lambda x: (-x[1], x[0]))[:top]]

        return {
            "totals": {key: self.totals.get(key, 0) for key in TOTAL_KEYS},
            "delivery_status": dict(sorted(self.status_counts.items())),
            "top_users": rows(self.users),
            "top_senders": rows(self.senders),
            "top_sender_domains": domains(self.sender_domains),
            "top_recipient_domains": domains(self.recipient_domains),
            "top_incoming_domains": domains(self.incoming_domains),
            "unparsed_postfix_lines": self.unparsed,
        }
