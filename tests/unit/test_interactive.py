from __future__ import annotations

import ipaddress
import unittest
from collections.abc import Iterator

from mail_sec_audit import interactive
from mail_sec_audit.i18n import Translator
from mail_sec_audit.runner import ForbiddenCommand
from tests.helpers import FakeRunner, Resp, config, run_scenario
from tests.unit.test_render import report


class FakeHost:
    def __init__(self, euid: int = 0, env: dict[str, str] | None = None) -> None:
        self.euid = euid
        self.env = env or {}


def routable(ip: str) -> bool:
    """Treat documentation ranges as routable so tests never use real addresses."""
    address = ipaddress.ip_address(ip)
    documentation = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    return address.is_global or any(address in ipaddress.ip_network(net) for net in documentation)


def answers(*items: str) -> Iterator[str]:
    yield from items


def responses() -> dict[tuple[str, ...], Resp]:
    return {
        ("fail2ban-client", "ping"): Resp("Server replied: pong\n"),
        ("fail2ban-client", "status"): Resp("Status\n|- Number of jail: 2\n`- Jail list: sshd, postfix-sasl\n"),
        ("fail2ban-client", "set"): Resp(""),
        ("fail2ban-client", "unban"): Resp("1\n"),
        ("logger",): Resp(""),
        ("sshd", "-T"): Resp("port 22\nport 2222\n"),
        ("ss", "-H", "-t", "-n", "state", "established"): Resp(
            "0 0 192.0.2.10:2222 203.0.113.50:51515\n0 0 192.0.2.10:443 198.51.100.77:40000\n"
        ),
        ("hostname", "-I"): Resp("192.0.2.10 2001:db8::10\n"),
    }


class InteractiveTest(unittest.TestCase):
    def run_menu(
        self,
        inputs: list[str],
        *,
        euid: int = 0,
        tty: bool = True,
        env: dict[str, str] | None = None,
        rep: object = None,
    ) -> tuple[FakeRunner, list[str]]:
        runner = FakeRunner(responses())
        said: list[str] = []
        it = answers(*inputs)
        r = rep or report()
        r.auth_statistics = {"ssh_failed": [["198.51.100.23", 500], ["203.0.113.50", 40]], "mail_failed": []}  # type: ignore[attr-defined]
        interactive.menu(
            config(),
            FakeHost(euid, env),  # type: ignore[arg-type]
            runner,
            Translator("en", strict=True),
            r,  # type: ignore[arg-type]
            ask=lambda _p: next(it),
            say=said.append,
            tty=tty,
            routable=routable,
        )
        return runner, said

    def test_ban_requires_typed_confirmation(self) -> None:
        runner, said = self.run_menu(["1", "1", "1", "ban", "0"])
        self.assertFalse(runner.called("fail2ban-client", "set"))
        self.assertIn("Cancelled", said)
        runner, said = self.run_menu(["1", "1", "1", "BAN", "0"])
        self.assertIn(("fail2ban-client", "set", "sshd", "banip", "198.51.100.23"), runner.calls)
        self.assertTrue(runner.called("logger", "-t", "mail-sec-audit"))
        self.assertFalse(runner.policy.allow_mutating, "mutations stay disabled after the action")

    def test_open_ssh_sessions_own_and_private_addresses_are_protected(self) -> None:
        for ip in ("203.0.113.50", "192.0.2.10", "2001:db8::10", "10.0.0.5", "127.0.0.1", "not-an-ip"):
            with self.subTest(ip=ip):
                runner, _said = self.run_menu(["1", "m", ip, "0"])
                self.assertFalse(runner.called("fail2ban-client", "set"))
        _, said = self.run_menu(
            ["1", "m", "198.51.100.9", "0"], env={"SSH_CONNECTION": "198.51.100.9 50000 192.0.2.10 22"}
        )
        self.assertTrue(any("Refused" in line for line in said))

    def test_unban(self) -> None:
        runner, _ = self.run_menu(["2", "198.51.100.23", "UNBAN", "0"])
        self.assertIn(("fail2ban-client", "unban", "198.51.100.23"), runner.calls)

    def test_preconditions(self) -> None:
        runner, said = self.run_menu([], tty=False)
        self.assertEqual(runner.calls, [])
        self.assertIn("not a terminal", said[0])
        runner, said = self.run_menu([], euid=1000)
        self.assertEqual(runner.calls, [])
        self.assertIn("needs root", said[0])

    def test_mutations_are_refused_outside_the_menu(self) -> None:
        runner = FakeRunner(responses())
        with self.assertRaises(ForbiddenCommand):
            runner.run(["fail2ban-client", "set", "sshd", "banip", "198.51.100.23"])

    def test_audit_never_mutates(self) -> None:
        scenario = run_scenario(responses=responses())
        self.assertFalse(scenario.runner.called("fail2ban-client", "set"))
        self.assertFalse(scenario.runner.called("logger"))


if __name__ == "__main__":
    unittest.main()
