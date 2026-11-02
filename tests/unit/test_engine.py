from __future__ import annotations

import io
import os
import signal
import tempfile
import threading
import unittest
from collections.abc import Iterable
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from mail_sec_audit import app
from mail_sec_audit.model import Finding, Status, exit_code_for
from mail_sec_audit.rules import run_checks
from mail_sec_audit.rules.base import Check, Ctx
from tests.helpers import Resp, config, run_scenario


class Crashing:
    CHECK = Check("CTX.CRASH")

    @staticmethod
    def run(ctx: Ctx) -> Iterable[Finding]:
        raise RuntimeError("boom")


class Fine:
    CHECK = Check("CTX.FINE")

    @staticmethod
    def run(ctx: Ctx) -> Iterable[Finding]:
        from mail_sec_audit.rules.base import Builder

        return [Builder(Fine.CHECK).ok(key="ctx.privileges.ok")]


class EngineTest(unittest.TestCase):
    def test_crashing_rule_becomes_unknown_and_report_continues(self) -> None:
        ctx = Ctx(config=config(), host=mock.Mock(), facts=mock.Mock(), completeness=mock.Mock())
        findings = run_checks(ctx, [Crashing, Fine])
        self.assertEqual([f.status for f in findings], [Status.UNKNOWN, Status.OK])
        self.assertEqual(findings[0].reason, "internal_error")
        self.assertIn("RuntimeError", findings[0].params["detail"])

    def test_exit_codes(self) -> None:
        self.assertEqual(exit_code_for([Status.OK, Status.INFO, Status.NA]), 0)
        self.assertEqual(exit_code_for([Status.OK, Status.UNKNOWN]), 1)
        self.assertEqual(exit_code_for([Status.WARN]), 1)
        self.assertEqual(exit_code_for([Status.WARN, Status.FAIL, Status.UNKNOWN]), 2)

    def test_context_rules_for_root_and_user(self) -> None:
        root = run_scenario(responses={("hostname", "-f"): Resp("mx1.example.org\n")})
        self.assertEqual(root.status("CTX.PRIVILEGES"), Status.OK)
        self.assertEqual(root.status("CTX.FQDN"), Status.OK)
        user = run_scenario(euid=1000, args=("--hostname", "localhost"))
        self.assertEqual(user.status("CTX.PRIVILEGES"), Status.WARN)
        self.assertEqual(user.status("CTX.FQDN"), Status.WARN)


class ProcessTest(unittest.TestCase):
    """Report file, lock and signal handling through app.run_audit."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="msa-app.")
        self.env = {"XDG_RUNTIME_DIR": self.tmp.name}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_main(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=False), redirect_stdout(out), redirect_stderr(err):
            code = app.main(["--lang", "en", "--platform", "generic", *args])
        return code, out.getvalue(), err.getvalue()

    def test_report_exists_and_lock_busy(self) -> None:
        existing = os.path.join(self.tmp.name, "exists.txt")
        open(existing, "w").close()
        code, _, err = self.run_main("--report", existing)
        self.assertEqual(code, 73, err)
        from mail_sec_audit.safefile import default_lock_path, single_instance

        with single_instance(default_lock_path(os.geteuid(), dict(self.env))):
            code, _, err = self.run_main("--report", os.path.join(self.tmp.name, "new.txt"))
        self.assertEqual(code, 75, err)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "new.txt")), "report created while lock busy")

    def test_signal_stops_cleans_up_and_removes_partial_report(self) -> None:
        report = os.path.join(self.tmp.name, "partial.txt")
        real_build = app.build_report

        def slow_build(*a: object, **kw: object) -> object:
            threading.Timer(0.1, os.kill, (os.getpid(), signal.SIGTERM)).start()
            threading.Event().wait(5)
            return real_build(*a, **kw)  # type: ignore[arg-type]

        with mock.patch.object(app, "build_report", slow_build):
            code, _, err = self.run_main("--report", report)
        self.assertEqual(code, 128 + signal.SIGTERM, err)
        self.assertIn("SIGTERM", err)
        self.assertFalse(os.path.exists(report))


if __name__ == "__main__":
    unittest.main()
