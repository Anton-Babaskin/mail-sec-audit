from __future__ import annotations

import datetime as dt
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mail_sec_audit import __version__, cli
from mail_sec_audit.app import main
from mail_sec_audit.i18n import select_language
from tests.helpers import NOW


def code(*args: str) -> int:
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return main(list(args))


class CliTest(unittest.TestCase):
    def test_help_and_version(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["--help"]), 0)
        self.assertIn("--days", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["--version"]), 0)
        self.assertEqual(out.getvalue().strip(), f"mail-sec-audit {__version__}")

    def test_usage_errors_exit_64(self) -> None:
        cases = [
            *[
                (option,)
                for option in (
                    "--hostname",
                    "--domain",
                    "--dkim-selector",
                    "--from",
                    "--to",
                    "--platform",
                    "--format",
                    "--report",
                    "--append-report",
                    "--lang",
                    "--days",
                    "--mail-top",
                )
            ],
            ("--hostname", "--deep"),
            ("--days", "0"),
            ("--days", "999999999999999999999999"),
            ("--days", "3651"),
            ("--mail-top", "101"),
            ("--from", "2026-02-31"),
            ("--from", "26-02-01"),
            ("--from", "2026-08-18", "--to", "2026-08-17"),
            ("--platform", "exchange"),
            ("--format", "yaml"),
            ("--lang", "de"),
            ("--format", "json", "--append-report", "/tmp/unused-mail-audit.json"),
            ("--format", "fleetops", "--interactive"),
            ("--format", "json", "--interactive"),
            ("--report", "/tmp/one", "--report", "/tmp/two"),
            ("--report", "/tmp/one", "--append-report", "/tmp/two"),
            ("--hostname", "bad name"),
            ("--domain", "-example.org"),
            ("--does-not-exist",),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(code(*args), 64)

    def test_allowed_ports(self) -> None:
        self.assertEqual(cli.parse_ports("10050 9100"), (10050, 9100))
        for bad in ("443 invalid", "70000", "0", "123456"):
            with self.subTest(bad=bad), self.assertRaises(cli.UsageError):
                cli.parse_ports(bad)

    def test_period_semantics_match_2_3(self) -> None:
        start, end, days = cli.compute_period(7, None, None, NOW)
        self.assertEqual((end - start).days, 7)
        self.assertEqual((start.hour, start.minute), (0, 0))
        self.assertEqual(days, 8)
        start, end, days = cli.compute_period(3, None, dt.date(2026, 8, 17), NOW)
        self.assertEqual(start.date(), dt.date(2026, 8, 15))
        self.assertEqual((end.hour, end.minute, end.second), (23, 59, 59))
        self.assertEqual(days, 3)
        start, end, days = cli.compute_period(7, dt.date(2026, 8, 17), dt.date(2026, 8, 17), NOW)
        self.assertEqual(days, 1)

    def test_language_selection(self) -> None:
        self.assertEqual(select_language("en", {"LANG": "ru_RU.UTF-8"}), "en")
        self.assertEqual(select_language(None, {"LANG": "ru_RU.UTF-8"}), "ru")
        self.assertEqual(select_language(None, {"LC_ALL": "C.UTF-8", "LANG": "ru_RU.UTF-8"}), "en")
        self.assertEqual(select_language(None, {"LC_MESSAGES": "ru_UA.UTF-8"}), "ru")
        self.assertEqual(select_language(None, {}), "en")

    def test_error_messages_follow_lang(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            main(["--lang", "ru", "--days", "0"])
        self.assertIn("--days требует число", err.getvalue())
        err = io.StringIO()
        with redirect_stderr(err):
            main(["--lang", "en", "--days", "0"])
        self.assertIn("--days requires a number", err.getvalue())

    def test_interactive_alias(self) -> None:
        parsed = cli.parse(["--manage-bans"], {}, NOW)
        assert isinstance(parsed, cli.Config)
        self.assertTrue(parsed.interactive)


if __name__ == "__main__":
    unittest.main()
