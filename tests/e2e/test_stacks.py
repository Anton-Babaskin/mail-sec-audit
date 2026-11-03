"""End-to-end scenarios per mail stack with a fake runner, fixture trees and
a fake TLS prober.

Log line shapes follow the stacks' documented formats and source code
(MIAB setup/mail-*.sh, mailcow master.cf, iRedMail conf/*). They are
ASSUMED shapes: tests/fixtures/shapes/<stack>/ with real lines does not
exist yet. Only .example domains and documentation IP ranges are used.
"""

from __future__ import annotations

import unittest

from mail_sec_audit.facts.tls import Handshake, Target
from mail_sec_audit.model import Status
from tests.helpers import Resp, Responses, run_scenario

CERT_OK = (
    "subject=CN = mx1.example.org\nissuer=C = US, O = Let's Encrypt, CN = R11\n"
    "notBefore=Oct  1 00:00:00 2026 GMT\nnotAfter=Dec 30 00:00:00 2026 GMT\n"
    "Hostname mx1.example.org does match certificate\n"
)


class Prober:
    def __init__(self, ok_ports: tuple[int, ...] = (465, 993), legacy: dict[int, str] | None = None) -> None:
        self.ok_ports = ok_ports
        self.legacy_results = legacy or {}
        self.handshakes: list[Target] = []

    def handshake(self, target: Target, server_name: str) -> Handshake:
        self.handshakes.append(target)
        if target.port in self.ok_ports:
            return Handshake(target, True, "TLSv1.3", b"\x30\x03\x02\x01\x00")
        return Handshake(target, False, error="STARTTLS not offered")

    def legacy(self, target: Target, version: str) -> str:
        return self.legacy_results.get(target.port, "rejected")


def dig(rcode: str, *answers: str) -> Resp:
    lines = [";; Got answer:", f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 1", ""]
    return Resp("\n".join(lines + list(answers)) + "\n")


def dns_responses() -> Responses:
    base = ("dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer")
    return {
        (*base, "MX", "example.org"): dig("NOERROR", "example.org. 300 IN MX 10 mx1.example.org."),
        (*base, "TXT", "example.org"): dig(
            "NOERROR",
            'example.org. 300 IN TXT "v=spf1 mx " "-all"',
            'example.org. 300 IN TXT "google-site-verification=x"',
        ),
        (*base, "TXT", "_dmarc.example.org"): dig("NOERROR", '_dmarc.example.org. 300 IN TXT "v=DMARC1; p=none"'),
        (*base, "TXT", "_mta-sts.example.org"): dig("NXDOMAIN"),
        (*base, "TXT", "_smtp._tls.example.org"): dig("SERVFAIL"),
        (*base, "A", "mx1.example.org"): dig("NOERROR", "mx1.example.org. 300 IN A 192.0.2.25"),
        (*base, "-x", "192.0.2.25"): dig("NOERROR", "25.2.0.192.in-addr.arpa. 300 IN PTR mx1.example.org."),
    }


def postfix_responses(prefix: tuple[str, ...] = ()) -> Responses:
    return {
        (*prefix, "postconf", "-x", "smtpd_relay_restrictions"): Resp(
            "smtpd_relay_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination\n"
            "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unlisted_recipient\n"
            "mynetworks = 127.0.0.0/8 [::1]/128\nmynetworks_style = host\nvirtual_mailbox_base =\nmail_version = 3.6.4\n"
        ),
        (*prefix, "postconf", "-x", "-P"): Resp("submission/inet/smtpd_sasl_auth_enable = yes\n"),
        (*prefix, "postconf", "-M"): Resp(
            "smtp       inet  n       -       y       -       -       smtpd\n"
            "submission inet  n       -       y       -       -       smtpd\n"
        ),
        (*prefix, "postqueue", "-j"): Resp(""),
    }


SS_MAIL = (
    "tcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:*\n"
    "tcp LISTEN 0 100 0.0.0.0:465 0.0.0.0:*\n"
    "tcp LISTEN 0 100 0.0.0.0:993 0.0.0.0:*\n"
    "tcp LISTEN 0 100 0.0.0.0:12340 0.0.0.0:*\n"
    "tcp LISTEN 0 100 127.0.0.1:10025 0.0.0.0:*\n"
)

MIAB_LOG = (
    "Nov  1 10:00:00 mx1 postfix/submission/smtpd[10]: 4AB12C3D4E: client=unknown[203.0.113.20], "
    "sasl_method=PLAIN, sasl_username=alice@example.org\n"
    "Nov  1 10:00:01 mx1 postfix/qmgr[11]: 4AB12C3D4E: from=<alice@example.org>, size=2048, nrcpt=1 (queue active)\n"
    "Nov  1 10:00:02 mx1 postfix/smtp[12]: 4AB12C3D4E: to=<bob@remote.example>, relay=mx.remote.example[198.51.100.7]:25, "
    "delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 Ok)\n"
    "Nov  1 10:00:03 mx1 postfix/qmgr[11]: 4AB12C3D4E: removed\n"
    "Nov  1 11:00:00 mx1 postfix/qmgr[11]: 5BC23D4E5F: from=<news@remote.example>, size=900, nrcpt=1 (queue active)\n"
    "Nov  1 11:00:01 mx1 postfix/lmtp[13]: 5BC23D4E5F: to=<alice@example.org>, relay=127.0.0.1[127.0.0.1]:10025, "
    "delay=0.2, delays=0/0/0/0.2, dsn=2.0.0, status=sent (250 2.0.0 <alice@example.org> Saved)\n"
    "Nov 01 11:00:01 lmtp(alice@example.org)<2001><abc>: Info: msgid=<1@remote.example>: saved mail to INBOX\n"
    "Nov 01 12:00:00 imap-login: Info: Disconnected: Connection closed (auth failed, 2 attempts in 4 secs): "
    "user=<alice@example.org>, method=PLAIN, rip=203.0.113.66, lip=192.0.2.25, TLS\n"
)


def miab() -> tuple[dict[str, str], Responses]:
    files = {
        "/etc/mailinabox.conf": "STORAGE_ROOT=/home/user-data\nPRIMARY_HOSTNAME=mx1.example.org\n",
        "/usr/local/bin/mailinabox": "#!/bin/bash\ncd /root/mailinabox\nsource setup/start.sh\n",
        "/root/mailinabox/.git/HEAD": "ref: refs/heads/main\n",
        "/home/user-data/mail/mailboxes/example.org/alice/.keep": "",
        "/home/user-data/backup/encrypted/duplicity-full.vol1.difftar.gpg": "",
        "/var/log/mail.log": MIAB_LOG,
        "/run/systemd/system/.keep": "",
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n',
        "/boot/vmlinuz-6.8.0-45-generic": "",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser-data:x:1001:1001::/home/user-data:/usr/sbin/nologin\n",
    }
    responses: Responses = {
        ("hostname", "-f"): Resp("mx1.example.org\n"),
        ("systemctl", "show"): Resp(
            "Id=postfix.service\nLoadState=loaded\nActiveState=active\n\n"
            "Id=dovecot.service\nLoadState=loaded\nActiveState=active\n\n"
            "Id=opendkim.service\nLoadState=loaded\nActiveState=active\n\n"
            "Id=spampd.service\nLoadState=loaded\nActiveState=failed\n\n"
            "Id=nginx.service\nLoadState=loaded\nActiveState=active\n"
        ),
        ("postconf",): Resp(""),
        ("doveconf", "-h", "ssl_min_protocol"): Resp("TLSv1.2\n"),
        ("doveconf", "-h", "ssl"): Resp("required\n"),
        ("doveconf", "-h", "auth_allow_cleartext"): Resp(
            "", rc=89, err="doveconf: Fatal: Unknown setting: auth_allow_cleartext"
        ),
        ("doveconf", "-h", "disable_plaintext_auth"): Resp("yes\n"),
        ("git",): Resp("v78\n"),
        ("ss", "-H", "-l", "-n", "-t", "-u"): Resp(SS_MAIL),
        ("openssl", "x509"): Resp(CERT_OK),
        ("journalctl",): Resp(""),
        ("apt-get",): Resp("Reading package lists...\n"),
        ("sshd", "-T"): Resp(
            "port 22\npermitrootlogin prohibit-password\npasswordauthentication no\npubkeyauthentication yes\nkbdinteractiveauthentication no\nx11forwarding no\nmaxauthtries 6\n"
        ),
        ("ufw", "status", "verbose"): Resp("Status: active\n"),
        ("fail2ban-client", "ping"): Resp("Server replied: pong\n"),
        ("fail2ban-client", "status"): Resp("`- Jail list:\tdovecot, postfix-sasl, sshd\n"),
        ("fail2ban-client", "status", "sshd"): Resp("   |- Currently banned:\t3\n   |- Total banned:\t41\n"),
        ("passwd", "-S", "-a"): Resp("root P 2026-01-01 0 99999 7 -1\n"),
        ("df", "-P", "-B1"): Resp(
            "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/sda1 100 40 60 40% /\n"
        ),
        ("df", "-P", "-i"): Resp("Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 100 5 95 5% /\n"),
        **postfix_responses(),
        **dns_responses(),
    }
    return files, responses


class MailInABoxTest(unittest.TestCase):
    def test_stack(self) -> None:
        files, responses = miab()
        prober = Prober()
        s = run_scenario(files, responses, args=("--domain", "example.org"), prober=prober)
        platform = s.get("CTX.PLATFORM")
        self.assertEqual((platform.params["platform"], platform.params["version"]), ("mailinabox", "v78"))
        self.assertFalse(any(call[0] == "mailinabox" for call in s.runner.calls))
        git = next(c for c in s.runner.calls if c[0] == "git")
        self.assertEqual(git[git.index("-C") + 1], "/root/mailinabox")
        self.assertEqual(s.status("STACK.SERVICE@postfix.service"), Status.OK)
        self.assertEqual(s.status("STACK.SERVICE@spampd.service"), Status.WARN)
        self.assertEqual(s.ids("NET."), ["NET.LISTENERS"], "12340 is expected on Mail-in-a-Box")
        self.assertEqual(s.status("MTA.RELAY_RESTRICTIONS"), Status.OK)
        self.assertEqual(s.status("MTA.MYNETWORKS"), Status.OK)
        stats = s.report.mail_statistics
        assert stats is not None
        self.assertEqual(stats["totals"]["outbound_messages"], 1)
        self.assertEqual(stats["totals"]["incoming_messages"], 1)
        self.assertEqual(stats["totals"]["authenticated_submissions"], 1)
        self.assertEqual(s.get("AUTH.MAIL_FAILURES").params["failed"], 2)
        self.assertEqual((s.report.auth_statistics or {})["mail_failed"], [["203.0.113.66", 2]])
        self.assertEqual(s.status("QUEUE.SIZE"), Status.OK)
        self.assertEqual(s.status("TLS.HANDSHAKE@465"), Status.OK)
        self.assertEqual(s.status("TLS.HANDSHAKE@25"), Status.WARN)
        self.assertEqual(s.status("TLS.CERT_EXPIRY@465"), Status.OK)
        self.assertEqual(s.status("TLS.CERT_NAME@993"), Status.OK)
        self.assertEqual(s.status("TLS.DOVECOT_MIN_PROTOCOL"), Status.OK)
        self.assertEqual(s.status("DNS.SPF"), Status.OK)
        self.assertEqual(s.get("DNS.DMARC").key, "dns.dmarc.monitor")
        self.assertEqual(s.status("DNS.MTA_STS"), Status.INFO)
        self.assertEqual(s.status("DNS.TLS_RPT"), Status.UNKNOWN, "SERVFAIL is not 'absent'")
        self.assertEqual(s.status("DNS.PTR@192.0.2.25"), Status.OK)
        self.assertEqual(s.status("DISK.MAIL_STORAGE"), Status.INFO)
        self.assertTrue(
            any("/home/user-data/backup/encrypted" in line for line in s.get("BACKUP.INDICATORS").evidence[0].excerpt)
        )
        self.assertIn("tls:127.0.0.1:465", s.report.completeness.local_probes)
        self.assertIn("dns:TXT _dmarc.example.org", s.report.completeness.external_probes)
        self.assertNotIn("TLS.LEGACY_PROTOCOLS@465", s.ids())

    def test_no_dns_without_domain(self) -> None:
        files, responses = miab()
        s = run_scenario(files, responses)
        self.assertFalse(any(call[0] == "dig" for call in s.runner.calls))
        self.assertEqual(s.status("DNS.SPF"), Status.NA)
        self.assertEqual(s.get("DNS.SPF").reason, "not_requested")

    def test_unreadable_log_is_unknown(self) -> None:
        files, responses = miab()
        s = run_scenario(files, responses, euid=1000, denied=frozenset({"/var/log/mail.log"}))
        self.assertEqual(s.status("FLOW.STATS"), Status.UNKNOWN)
        self.assertEqual(s.get("FLOW.STATS").reason, "permission_denied")
        self.assertEqual(s.status("AUTH.MAIL_FAILURES"), Status.UNKNOWN)

    def test_legacy_tls_deep(self) -> None:
        files, responses = miab()
        prober = Prober(ok_ports=(25, 465, 993), legacy={25: "accepted", 465: "client_unsupported", 993: "accepted"})
        s = run_scenario(files, responses, args=("--deep",), prober=prober)
        self.assertEqual(s.status("TLS.LEGACY_PROTOCOLS@25"), Status.INFO)
        self.assertEqual(s.status("TLS.LEGACY_PROTOCOLS@465"), Status.UNKNOWN)
        self.assertEqual(s.status("TLS.LEGACY_PROTOCOLS@993"), Status.WARN)


MAILCOW_POSTFIX = "a" * 64
MAILCOW_DOVECOT = "b" * 64


def mailcow() -> tuple[dict[str, str], Responses]:
    exec_postfix = ("docker", "exec", MAILCOW_POSTFIX)
    long_queue = "".join(f'{{"queue_name": "deferred", "queue_id": "4Xyz{i:07d}BcDfz"}}\n' for i in range(150))
    logs = (
        "2026-11-01T10:00:00.123456789Z Nov  1 11:00:00 abc postfix/qmgr[2]: 6CD34E5F6A: from=<a@example.org>, "
        "size=10, nrcpt=1 (queue active)\n"
        "2026-11-01T10:00:01.123456789Z Nov  1 11:00:01 abc enforced-tls-smtp/smtp[3]: 6CD34E5F6A: to=<x@remote.example>, "
        "relay=mx.remote.example[198.51.100.7]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)\n"
        "2026-11-01T10:00:02.5Z Nov  1 11:00:02 abc watchdog/smtpd[4]: 9FA67B8C9D: client=unknown[172.22.1.1]\n"
        "2026-11-01T10:00:03Z Nov  1 11:00:03 abc postfix/smtps/smtpd[5]: warning: unknown[203.0.113.77]: "
        "SASL LOGIN authentication failed: UGFzc3dvcmQ6\n"
    )
    files = {"/run/systemd/system/.keep": ""}
    responses: Responses = {
        ("hostname", "-f"): Resp("mx1.example.org\n"),
        ("docker", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.service=postfix-mailcow"): Resp(
            f"{MAILCOW_POSTFIX}\trunning\n"
        ),
        ("docker", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.service=dovecot-mailcow"): Resp(
            f"{MAILCOW_DOVECOT}\trunning\n"
        ),
        ("docker", "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.service=netfilter-mailcow"): Resp(
            f"{'c' * 64}\trunning\n"
        ),
        ("docker", "ps", "-a", "--filter", "label=com.docker.compose.project=mailcowdockerized"): Resp(
            "mailcowdockerized-postfix-mailcow-1\trunning\tUp 3 days\n"
            "mailcowdockerized-rspamd-mailcow-1\trunning\tUp 3 days (unhealthy)\n"
        ),
        ("docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project"}}'): Resp(
            "mailcowdockerized\n"
        ),
        ("docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'): Resp(
            "/opt/mailcow-dockerized\n"
        ),
        (
            "docker",
            "inspect",
            "--format",
            '{{range .Mounts}}{{if eq .Destination "/var/vmail"}}{{.Source}}{{end}}{{end}}',
        ): Resp("/var/lib/docker/volumes/mailcowdockerized_vmail-vol-1/_data\n"),
        ("docker", "logs"): lambda argv: Resp(logs) if argv[-1] == MAILCOW_POSTFIX else Resp(""),
        ("git",): Resp("2026-09\n"),
        **postfix_responses(exec_postfix),
        (*exec_postfix, "postconf", "-x", "-P"): Resp(
            "smtpd/pass/smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination\n"
        ),
        (*exec_postfix, "postconf", "-M"): Resp(
            "smtp       inet  n       -       n       -       1       postscreen\n"
            "smtpd      pass  -       -       n       -       -       smtpd\n"
        ),
        (*exec_postfix, "postconf", "-x", "smtpd_relay_restrictions"): Resp(
            "smtpd_relay_restrictions = permit\nsmtpd_recipient_restrictions = permit_mynetworks\n"
            "mynetworks = 127.0.0.0/8 172.22.1.0/24\nmail_version = 3.7.11\n"
        ),
        (*exec_postfix, "postqueue", "-j"): Resp(long_queue),
        ("docker", "exec", MAILCOW_DOVECOT, "doveconf", "-h", "ssl_min_protocol"): Resp("TLSv1.2\n"),
        ("docker", "exec", MAILCOW_DOVECOT, "doveconf"): Resp("yes\n"),
        ("ss", "-H", "-l", "-n", "-t", "-u"): Resp(SS_MAIL.replace("0.0.0.0:12340", "0.0.0.0:443")),
        ("openssl", "x509"): Resp(CERT_OK),
        ("iptables", "-S"): Resp("-P INPUT ACCEPT\n-N DOCKER\n-A FORWARD -j DOCKER-USER\n"),
    }
    return files, responses


class MailcowTest(unittest.TestCase):
    def test_stack(self) -> None:
        files, responses = mailcow()
        files["/proc/net/ip_tables_names"] = "filter\n"
        s = run_scenario(files, responses, prober=Prober())
        self.assertEqual(s.get("CTX.PLATFORM").params["platform"], "mailcow")
        self.assertEqual(s.status("STACK.SERVICE@postfix-mailcow"), Status.OK)
        self.assertEqual(s.status("STACK.CONTAINERS_HEALTH"), Status.FAIL)
        relay = s.get("MTA.RELAY_RESTRICTIONS")
        self.assertEqual(relay.status, Status.OK, "smtpd/pass override applies behind postscreen")
        self.assertEqual(relay.params["service"], "smtpd/pass")
        self.assertEqual(s.status("QUEUE.SIZE"), Status.WARN)
        self.assertEqual(s.get("QUEUE.SIZE").params["count"], 150)
        self.assertEqual(s.status("BRUTE.PROTECTION"), Status.OK)
        self.assertEqual(s.status("FW.HOST_FIREWALL"), Status.FAIL, "Docker chains are not a host firewall")
        stats = s.report.mail_statistics
        assert stats is not None
        self.assertEqual(stats["totals"]["outbound_messages"], 1, "enforced-tls-smtp/smtp is counted")
        self.assertEqual(stats["totals"]["tracked_queue_ids"], 1, "watchdog lines are ignored")
        self.assertEqual(s.get("AUTH.MAIL_FAILURES").params["failed"], 1)
        self.assertTrue(
            all(c[:2] != ("docker", "exec") or c[2] in (MAILCOW_POSTFIX, MAILCOW_DOVECOT) for c in s.runner.calls)
        )
        self.assertFalse(any("update.sh" in " ".join(c) for c in s.runner.calls))
        self.assertIn("/var/lib/docker/volumes", s.get("DISK.MAIL_STORAGE").params["path"])

    def test_open_relay_without_pass_override(self) -> None:
        files, responses = mailcow()
        exec_postfix = ("docker", "exec", MAILCOW_POSTFIX)
        responses = dict(responses)
        key = (*exec_postfix, "postconf", "-x", "-P")
        responses[key] = Resp("")
        s = run_scenario(files, responses, prober=Prober())
        self.assertEqual(s.status("MTA.RELAY_RESTRICTIONS"), Status.FAIL)


IREDMAIL_LOG = (
    "Nov  1 10:00:00 mx1 postfix/submission/smtpd[1]: 7DE45F6A7B: client=unknown[192.0.2.10], sasl_method=LOGIN, "
    "sasl_username=carol@example.org\n"
    "Nov  1 10:00:01 mx1 postfix/qmgr[2]: 7DE45F6A7B: from=<carol@example.org>, size=1000, nrcpt=1 (queue active)\n"
    "Nov  1 10:00:02 mx1 postfix/smtp[3]: 7DE45F6A7B: to=<dave@remote.example>, relay=127.0.0.1[127.0.0.1]:10026, "
    "delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): 250 2.0.0 Ok: queued as 8EF56A7B8C)\n"
    "Nov  1 10:00:03 mx1 postfix/qmgr[2]: 7DE45F6A7B: removed\n"
    "Nov  1 10:00:04 mx1 postfix/qmgr[2]: 8EF56A7B8C: from=<carol@example.org>, size=1400, nrcpt=1 (queue active)\n"
    "Nov  1 10:00:05 mx1 postfix/smtp[4]: 8EF56A7B8C: to=<dave@remote.example>, relay=mx.remote.example[198.51.100.7]:25, "
    "delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)\n"
    "Nov  1 10:00:06 mx1 postfix/qmgr[2]: 8EF56A7B8C: removed\n"
)
IREDMAIL_DOVECOT = (
    "Nov  1 12:00:00 mx1 dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<x@example.org>, "
    "method=PLAIN, rip=198.51.100.99, lip=192.0.2.25, TLS\n"
)


class IRedMailTest(unittest.TestCase):
    def test_amavis_hop_counted_once(self) -> None:
        files = {
            "/etc/iredmail-release": "1.7.4 MARIADB edition.\n",
            "/var/log/mail.log": IREDMAIL_LOG,
            "/var/log/dovecot/imap.log": IREDMAIL_DOVECOT,
            "/var/vmail/.keep": "",
            "/run/systemd/system/.keep": "",
        }
        responses: Responses = {
            ("hostname", "-f"): Resp("mx1.example.org\n"),
            ("systemctl", "show"): Resp(
                "Id=postfix.service\nLoadState=loaded\nActiveState=active\n\n"
                "Id=dovecot.service\nLoadState=loaded\nActiveState=active\n\n"
                "Id=amavis.service\nLoadState=loaded\nActiveState=active\n"
            ),
            ("postconf",): Resp(""),
            ("doveconf",): Resp("TLSv1.2\n"),
            **postfix_responses(),
        }
        s = run_scenario(files, responses)
        platform = s.get("CTX.PLATFORM")
        self.assertEqual(
            (platform.params["platform"], platform.params["version"]), ("iredmail", "1.7.4 MARIADB edition.")
        )
        stats = s.report.mail_statistics
        assert stats is not None
        totals = stats["totals"]
        self.assertEqual((totals["outbound_messages"], totals["internal_hops"]), (1, 1))
        self.assertEqual(totals["authenticated_outbound_messages"], 1)
        self.assertEqual(stats["top_users"][0]["address"], "carol@example.org")
        self.assertEqual(s.get("AUTH.MAIL_FAILURES").params["failed"], 1)
        self.assertEqual(s.status("STACK.SERVICE@amavis.service"), Status.OK)
        self.assertEqual(s.get("DISK.MAIL_STORAGE").params["path"], "/var/vmail")


class OtherMtaTest(unittest.TestCase):
    def test_generic_postfix_open_relay(self) -> None:
        responses = dict(postfix_responses())
        responses[("postconf", "-x", "smtpd_relay_restrictions")] = Resp(
            "smtpd_relay_restrictions = permit_mynetworks, permit, reject_unauth_destination\n"
            "smtpd_recipient_restrictions = permit_mynetworks\nmynetworks = 0.0.0.0/0\n"
        )
        responses[("systemctl", "show")] = Resp("Id=postfix.service\nLoadState=loaded\nActiveState=inactive\n")
        s = run_scenario({"/run/systemd/system/.keep": ""}, responses)
        self.assertEqual(s.get("CTX.PLATFORM").params["platform"], "generic")
        self.assertEqual(s.status("MTA.RELAY_RESTRICTIONS"), Status.FAIL)
        self.assertEqual(s.status("MTA.MYNETWORKS"), Status.FAIL)
        self.assertEqual(s.status("STACK.SERVICE@postfix.service"), Status.FAIL)
        self.assertEqual(s.status("FLOW.STATS"), Status.UNKNOWN)

    def test_exim(self) -> None:
        responses: Responses = {
            ("systemctl", "show"): Resp("Id=exim4.service\nLoadState=loaded\nActiveState=active\n"),
            ("exim4", "-bP"): Resp("primary_hostname = mx1.example.org\nrelay_from_hosts = *\n"),
            ("exim4", "-bpc"): Resp("5\n"),
        }
        s = run_scenario({"/run/systemd/system/.keep": ""}, responses)
        self.assertEqual(s.status("MTA.EXIM_RELAY_HOSTS"), Status.FAIL)
        self.assertEqual(s.get("QUEUE.SIZE").params["count"], 5)
        self.assertEqual(s.status("MTA.RELAY_RESTRICTIONS"), Status.NA)
        self.assertEqual(s.status("FLOW.STATS"), Status.NA)

    def test_sendmail(self) -> None:
        files = {
            "/run/systemd/system/.keep": "",
            "/etc/mail/sendmail.cf": "# generated\n",
            "/etc/mail/sendmail.mc": "FEATURE(`promiscuous_relay')dnl\nFEATURE(`relay_entire_domain')dnl\n",
        }
        responses: Responses = {
            ("systemctl", "show"): Resp("Id=sendmail.service\nLoadState=loaded\nActiveState=active\n"),
            ("mailq",): Resp("\t\tTotal requests: 2\n"),
        }
        s = run_scenario(files, responses)
        self.assertEqual(s.status("MTA.SENDMAIL_RELAY"), Status.FAIL)
        self.assertEqual(s.get("QUEUE.SIZE").params["count"], 2)
        self.assertFalse(any(c[0] == "sendmail" for c in s.runner.calls))

    def test_opensmtpd(self) -> None:
        files = {
            "/run/systemd/system/.keep": "",
            "/etc/smtpd.conf": 'action "outbound" relay\nmatch from any for any action "outbound"\n',
        }
        responses: Responses = {
            ("systemctl", "show"): Resp("Id=opensmtpd.service\nLoadState=loaded\nActiveState=active\n")
        }
        s = run_scenario(files, responses)
        self.assertEqual(s.status("MTA.OPENSMTPD_RELAY"), Status.FAIL)
        self.assertEqual(s.status("QUEUE.SIZE"), Status.NA)

    def test_no_mta(self) -> None:
        s = run_scenario({"/run/systemd/system/.keep": ""}, {("systemctl", "show"): Resp("")})
        self.assertEqual(s.status("STACK.MTA_DETECTED"), Status.FAIL)
        self.assertEqual(s.status("MTA.EXTERNAL_TEST"), Status.NA)


class JsonContractTest(unittest.TestCase):
    def test_ids_are_stable_across_conditions(self) -> None:
        """The same check keeps its ID whatever fired before it (R-07)."""
        files, responses = miab()
        first = run_scenario(files, responses)
        responses = dict(responses)
        responses[("sshd", "-T")] = Resp("port 22\npermitrootlogin yes\npasswordauthentication yes\n")
        second = run_scenario(files, responses)
        self.assertIn("SSH.X11_FORWARDING", first.ids())
        self.assertIn("SSH.X11_FORWARDING", second.ids())
        self.assertEqual(set(first.ids("DNS.")), set(second.ids("DNS.")))


if __name__ == "__main__":
    unittest.main()
