"""Log parsing: timestamps, headers, Postfix fields, statistics, auth counters.

Includes the hostile and edge cases from review R-13...R-20 and R-43.
All addresses use .example domains and documentation IP ranges.
"""

from __future__ import annotations

import datetime as dt
import unittest
from typing import Any

from mail_sec_audit.logs.auth import AuthCounter
from mail_sec_audit.logs.lines import parse_header
from mail_sec_audit.logs.postfix import parse_delivery, parse_qmgr, split_queue_id
from mail_sec_audit.logs.stats import MailStats
from mail_sec_audit.logs.timeparse import split_time

UTC = dt.timezone.utc
ANCHOR = dt.datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


def stats(*lines: str) -> dict[str, Any]:
    collector = MailStats()
    for line in lines:
        parsed = split_time(line, ANCHOR)
        assert parsed, line
        header = parse_header(parsed[1])
        assert header, line
        collector.feed(parsed[0], header)
    return collector.result(20)


def auth(*lines: str) -> AuthCounter:
    counter = AuthCounter()
    for line in lines:
        parsed = split_time(line, ANCHOR)
        assert parsed, line
        header = parse_header(parsed[1])
        assert header, line
        counter.feed_ssh(header)
        counter.feed_mail(header)
    return counter


T = "2026-08-17T10:00:0{}Z mail "
SENT = "relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)"


class TimeTest(unittest.TestCase):
    def test_forms(self) -> None:
        when, rest = split_time("2026-08-17T10:00:00.123456789Z mail postfix/smtp[1]: x", ANCHOR) or (None, "")
        self.assertEqual(when, dt.datetime(2026, 8, 17, 10, 0, 0, 123456, tzinfo=UTC))
        self.assertEqual(rest, "mail postfix/smtp[1]: x")
        when, _ = split_time("2026-11-02T13:25:36.000001+0300 mx1 sshd[1]: x", ANCHOR) or (None, "")
        self.assertEqual(when, dt.datetime(2026, 11, 2, 10, 25, 36, 1, tzinfo=UTC))
        docker = "2026-08-17T10:00:00.5Z Aug 17 13:00:00 abc postfix/qmgr[2]: ABCDE1: removed"
        when, rest = split_time(docker, ANCHOR) or (None, "")
        self.assertEqual(rest, "abc postfix/qmgr[2]: ABCDE1: removed")
        self.assertEqual(when, dt.datetime(2026, 8, 17, 10, 0, 0, 500000, tzinfo=UTC))

    def test_year_from_anchor_and_rollover(self) -> None:
        old_file = dt.datetime(2025, 11, 5, tzinfo=UTC)
        when, _ = split_time("Nov  1 10:00:00 mail postfix/qmgr[1]: X", old_file) or (None, "")
        assert when is not None
        self.assertEqual(when.year, 2025)
        new_year = dt.datetime(2026, 1, 1, 0, 30, tzinfo=UTC)
        when, _ = split_time("Dec 31 23:59:59 mail postfix/qmgr[1]: X", new_year) or (None, "")
        assert when is not None
        self.assertEqual(when.year, 2025)

    def test_timestamp_inside_message_does_not_count(self) -> None:
        self.assertIsNone(split_time("garbage postfix/smtpd[1]: helo=<2026-08-17T10:00:00Z>", ANCHOR))


class HeaderTest(unittest.TestCase):
    def test_shapes(self) -> None:
        h = parse_header("mx1 postfix/submission/smtpd[12]: warning: x")
        assert h
        self.assertEqual((h.host, h.tag, h.pid, h.postfix_process), ("mx1", "postfix/submission/smtpd", "12", "smtpd"))
        h = parse_header("lmtp(user@example.org)<12><abc>: Info: saved mail")
        assert h
        self.assertEqual(h.tag, "lmtp(user@example.org)<12><abc>")
        h = parse_header("abc enforced-tls-smtp/smtp[9]: 4AB12C3D4E: to=<a@b.example>")
        assert h
        self.assertEqual(h.postfix_process, "smtp")
        h = parse_header("mx1 smtpd[3]: 1a2b3c4d5e6f7a8b smtp connected")
        assert h
        self.assertIsNone(h.postfix_process, "OpenSMTPD smtpd has no slash")
        h = parse_header("abc watchdog/smtpd[3]: connect from x")
        assert h
        self.assertTrue(h.watchdog)

    def test_queue_ids(self) -> None:
        self.assertIsNotNone(split_queue_id("4AB12C3D4E: removed"))
        self.assertIsNotNone(split_queue_id("3Pt2mN2VXxznjll: removed"))
        for word in ("warning", "NOQUEUE", "statistics", "connect from x"):
            self.assertIsNone(split_queue_id(f"{word}: x"), word)


class PostfixFieldTest(unittest.TestCase):
    def test_quoted_recipient_cannot_fake_status(self) -> None:
        body = (
            'to=<"x, relay=a, delay=1, delays=1, dsn=2.0.0, status=sent (ok)"@remote.example>, '
            "relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=5.1.1, status=bounced (550 no)"
        )
        delivery = parse_delivery(body)
        assert delivery
        self.assertEqual(delivery.status, "bounced")
        self.assertTrue(delivery.recipient.startswith('"x, relay'))

    def test_response_text_cannot_fake_status(self) -> None:
        body = (
            "to=<a@remote.example>, relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, "
            "dsn=4.0.0, status=deferred (host said: 450 x, dsn=2.0.0, status=sent (fake))"
        )
        delivery = parse_delivery(body)
        assert delivery
        self.assertEqual(delivery.status, "deferred")

    def test_qmgr_size_from_structure(self) -> None:
        envelope = parse_qmgr('from=<"size=999999999"@attacker.example>, size=100, nrcpt=1 (queue active)')
        assert envelope
        self.assertEqual(envelope.size, 100)


class StatsTest(unittest.TestCase):
    def test_basic_flow_and_separate_counts(self) -> None:
        data = stats(
            T.format(0) + "postfix/submission/smtpd[1]: 4AB12C3D4E: client=unknown[192.0.2.10], "
            "sasl_method=PLAIN, sasl_username=alice@example.org",
            T.format(1) + "postfix/qmgr[2]: 4AB12C3D4E: from=<alice@example.org>, size=1000, nrcpt=2 (queue active)",
            T.format(2) + "postfix/smtp[3]: 4AB12C3D4E: to=<b@one.example>, " + SENT,
            T.format(3) + "postfix/smtp[3]: 4AB12C3D4E: to=<c@two.example>, relay=mx.two.example[198.51.100.8]:25, "
            "delay=1, delays=0/0/0/1, dsn=4.4.1, status=deferred (timeout)",
            T.format(4) + "postfix/smtp[3]: 4AB12C3D4E: to=<c@two.example>, relay=mx.two.example[198.51.100.8]:25, "
            "delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)",
            T.format(5) + "postfix/qmgr[2]: 4AB12C3D4E: removed",
        )
        totals = data["totals"]
        self.assertEqual(totals["outbound_messages"], 1)
        self.assertEqual(totals["outbound_deliveries"], 2)
        self.assertEqual(totals["deferred_deliveries"], 1)
        self.assertEqual(totals["authenticated_submissions"], 1)
        self.assertEqual(totals["outbound_bytes"], 1000)
        self.assertEqual(data["top_users"][0]["address"], "alice@example.org")
        self.assertEqual(
            {r["domain"]: r["count"] for r in data["top_recipient_domains"]}, {"one.example": 1, "two.example": 1}
        )

    def test_hostile_sasl_in_sender_is_not_authentication(self) -> None:
        data = stats(
            T.format(0) + "postfix/smtpd[1]: 4AB12C3D4E: client=unknown[203.0.113.9]",
            T.format(1)
            + 'postfix/qmgr[2]: 4AB12C3D4E: from=<"sasl_username=ceo"@attacker.example>, size=100, nrcpt=1 (queue active)',
            T.format(2) + "postfix/smtp[3]: 4AB12C3D4E: to=<victim@remote.example>, " + SENT,
        )
        self.assertEqual(data["totals"]["authenticated_submissions"], 0)
        self.assertEqual(data["top_users"], [])

    def test_warning_line_is_not_a_message(self) -> None:
        data = stats(
            T.format(0) + "postfix/smtpd[1]: warning: unknown[203.0.113.9]: SASL LOGIN authentication "
            "failed: UGFzc3dvcmQ6, sasl_username=admin"
        )
        self.assertEqual(data["totals"]["tracked_queue_ids"], 0)
        self.assertEqual(data["totals"]["authenticated_submissions"], 0)

    def test_loopback_content_filter_is_one_external_delivery(self) -> None:
        data = stats(
            T.format(0) + "postfix/submission/smtpd[1]: 7DE45F6A7B: client=unknown[192.0.2.10], sasl_method=PLAIN, "
            "sasl_username=alice@example.org",
            T.format(1) + "postfix/qmgr[2]: 7DE45F6A7B: from=<alice@example.org>, size=1000, nrcpt=1 (queue active)",
            T.format(2) + "postfix/smtp[3]: 7DE45F6A7B: to=<bob@remote.example>, relay=127.0.0.1[127.0.0.1]:10024, "
            "delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 8EF56A7B8C)",
            T.format(3) + "postfix/qmgr[2]: 7DE45F6A7B: removed",
            T.format(4) + "postfix/smtpd[5]: 8EF56A7B8C: client=localhost[127.0.0.1]",
            T.format(5) + "postfix/qmgr[2]: 8EF56A7B8C: from=<alice@example.org>, size=1400, nrcpt=1 (queue active)",
            T.format(6) + "postfix/smtp[4]: 8EF56A7B8C: to=<bob@remote.example>, " + SENT,
            T.format(7) + "postfix/qmgr[2]: 8EF56A7B8C: removed",
        )
        totals = data["totals"]
        self.assertEqual(totals["outbound_messages"], 1)
        self.assertEqual(totals["outbound_deliveries"], 1)
        self.assertEqual(totals["internal_hops"], 1)
        self.assertEqual(totals["authenticated_submissions"], 1)
        self.assertEqual(totals["authenticated_outbound_messages"], 1)
        self.assertEqual(data["top_users"][0]["messages"], 1)

    def test_miab_lmtp_to_spampd_is_local_delivery(self) -> None:
        data = stats(
            T.format(1) + "postfix/qmgr[2]: 5BC23D4E5F: from=<x@remote.example>, size=500, nrcpt=1 (queue active)",
            T.format(2) + "postfix/lmtp[3]: 5BC23D4E5F: to=<user@example.org>, relay=127.0.0.1[127.0.0.1]:10025, "
            "delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 <user@example.org> Saved)",
        )
        self.assertEqual(data["totals"]["incoming_messages"], 1)
        self.assertEqual(data["totals"]["outbound_messages"], 0)

    def test_mailcow_enforced_tls_and_watchdog(self) -> None:
        data = stats(
            T.format(1) + "postfix/qmgr[2]: 6CD34E5F6A: from=<a@example.org>, size=10, nrcpt=1 (queue active)",
            T.format(2) + "enforced-tls-smtp/smtp[3]: 6CD34E5F6A: to=<x@remote.example>, " + SENT,
            T.format(3) + "watchdog/smtpd[4]: 9FA67B8C9D: client=unknown[172.22.1.1]",
        )
        self.assertEqual(data["totals"]["outbound_messages"], 1)
        self.assertEqual(data["totals"]["tracked_queue_ids"], 1)


class AuthTest(unittest.TestCase):
    def test_ssh(self) -> None:
        counter = auth(
            "Nov  2 10:00:00 mx1 sshd[1]: Invalid user admin from 203.0.113.5 port 4000",
            "Nov  2 10:00:01 mx1 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 4000 ssh2",
            "Nov  2 10:00:02 mx1 sshd-session[2]: Failed password for root from ::ffff:198.51.100.1 port 1 ssh2",
            "Nov  2 10:00:03 mx1 sshd[3]: Accepted publickey for alice from 192.0.2.50 port 2 ssh2: ED25519 SHA256:x",
        )
        self.assertEqual((counter.ssh_failed, counter.ssh_invalid, counter.ssh_accepted), (2, 1, 1))
        self.assertEqual(counter.top(counter.ssh_failed_ips), [["198.51.100.1", 1], ["203.0.113.5", 1]])

    def test_mail_uses_rip_not_lip_and_ignores_aborted(self) -> None:
        counter = auth(
            "Nov 02 10:00:00 imap-login: Info: Disconnected: Connection closed (auth failed, 3 attempts in 15 secs): "
            "user=<u@example.org>, method=PLAIN, rip=203.0.113.7, lip=192.0.2.1, TLS",
            "Nov  2 10:00:01 mx1 dovecot: pop3-login: Aborted login (no auth attempts in 0 secs): user=<>, "
            "rip=203.0.113.8, lip=192.0.2.1",
            "Nov  2 10:00:02 mx1 dovecot: auth: passwd-file(u@example.org,203.0.113.7): unknown user",
            "Nov  2 10:00:03 mx1 postfix/submission/smtpd[9]: warning: unknown[198.51.100.9]: SASL LOGIN "
            "authentication failed: UGFzc3dvcmQ6",
        )
        self.assertEqual(counter.mail_failed, 4)
        self.assertEqual(counter.top(counter.mail_failed_ips), [["203.0.113.7", 3], ["198.51.100.9", 1]])
        self.assertNotIn("192.0.2.1", counter.mail_failed_ips)


if __name__ == "__main__":
    unittest.main()
