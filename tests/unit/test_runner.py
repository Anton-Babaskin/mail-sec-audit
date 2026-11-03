from __future__ import annotations

import unittest

from mail_sec_audit.runner import (
    RULES,
    ExecState,
    ForbiddenCommand,
    Lit,
    Policy,
    Rule,
    SystemRunner,
    child_env,
    failure_reason,
)
from mail_sec_audit.runner import CommandResult as R


class AllowlistTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = Policy()

    def refused(self, *argv: str) -> None:
        with self.assertRaises(ForbiddenCommand, msg=" ".join(argv)):
            self.policy.check(argv)

    def test_mailinabox_and_update_sh_are_refused_with_any_arguments(self) -> None:
        for argv in (
            ("mailinabox",),
            ("mailinabox", "--version"),
            ("/usr/local/bin/mailinabox", "--help"),
            ("update.sh",),
            ("update.sh", "--check"),
            ("/opt/mailcow-dockerized/update.sh", "--check"),
            ("docker", "exec", "abc123def456", "mailinabox", "--version"),
            ("docker", "exec", "abc123def456", "/usr/local/bin/mailinabox"),
            ("docker", "exec", "abc123def456", "update.sh"),
        ):
            self.refused(*argv)

    def test_programs_with_paths_are_refused(self) -> None:
        self.refused("/usr/sbin/postconf", "-h", "mynetworks")
        self.refused("./postconf", "-h", "mynetworks")

    def test_docker_is_limited_to_ps_inspect_logs_and_exec(self) -> None:
        self.policy.check(("docker", "inspect", "--format", "{{.Config.Image}}", "abc123def456"))
        self.policy.check(("docker", "logs", "--timestamps", "--since", "1761955200", "--until", "1762041599", "c1"))
        self.policy.check(("docker", "exec", "abc123def456", "postconf", "-h", "mynetworks"))
        self.policy.check(("docker", "exec", "abc123def456", "postqueue", "-j"))
        for argv in (
            ("docker", "exec", "-it", "abc123def456", "postconf", "-h", "mynetworks"),
            ("docker", "exec", "-u", "root", "abc123def456", "postconf"),
            ("docker", "exec", "--privileged", "abc123def456", "postconf"),
            ("docker", "exec", "abc123def456", "sh", "-c", "postconf"),
            ("docker", "exec", "abc123def456", "postfix", "reload"),
            ("docker", "exec", "abc123def456", "doveconf", "-x", "ssl_key"),
            ("docker", "exec", "abc123def456", "fail2ban-client", "set", "sshd", "banip", "192.0.2.1"),
            ("docker", "restart", "abc123def456"),
            ("docker", "compose", "pull"),
            ("docker", "rm", "abc123def456"),
            ("docker", "inspect", "--format", "{{json .}}", "abc123def456"),
            ("docker", "exec", "abc123def456"),
        ):
            self.refused(*argv)

    def test_service_management_and_package_changes_are_refused(self) -> None:
        for argv in (
            ("systemctl", "restart", "postfix.service"),
            ("systemctl", "reload", "postfix.service"),
            ("systemctl", "stop", "fail2ban.service"),
            ("postfix", "reload"),
            ("postsuper", "-d", "ALL"),
            ("apt-get", "upgrade"),
            ("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade", "-y"),
            ("dnf", "upgrade"),
            ("ufw", "disable"),
            ("iptables", "-F"),
            ("nft", "flush", "ruleset"),
            ("sendmail", "-bv", "root"),
            ("rpm", "-Va"),
            ("doveconf", "-x"),
            ("doveconf", "-h", "ssl_key"),
            ("postconf", "-e", "mynetworks=0.0.0.0/0"),
            ("postconf", "-h", "mynetworks=0.0.0.0/0"),
            ("crontab", "-u", "root", "-l"),
            ("cat", "/etc/shadow"),
            ("git", "-C", "/root/mailinabox", "pull"),
            ("sh", "-c", "id"),
            ("bash", "-c", "id"),
            ("python3", "-c", "print(1)"),
        ):
            self.refused(*argv)

    def test_mutating_commands_need_interactive_mode(self) -> None:
        argv = ("fail2ban-client", "set", "sshd", "banip", "203.0.113.7")
        self.refused(*argv)
        self.refused("logger", "-t", "mail-sec-audit", "--", "manual ban")
        self.policy.allow_mutating = True
        self.policy.check(argv)
        self.policy.check(("logger", "-t", "mail-sec-audit", "--", "manual ban ip=203.0.113.7 jail=sshd user=root"))
        self.refused("logger", "-t", "mail-sec-audit", "--", "line\nbreak")
        self.refused("docker", "exec", "abc123def456", "fail2ban-client", "set", "sshd", "banip", "203.0.113.7")

    def test_argument_shapes_are_validated(self) -> None:
        self.policy.check(("postconf", "-x", "-h", "smtpd_relay_restrictions", "mynetworks"))
        self.refused("postconf", "-x", "-h", "a;b")
        self.policy.check(("dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer", "TXT", "_dmarc.example.org"))
        self.refused("dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer", "AXFR", "example.org")
        self.refused("dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer", "TXT", "-f/etc/shadow")
        git = ("git", "-c", "core.fsmonitor=false", "--no-pager", "--no-optional-locks", "-C")
        self.policy.check((*git, "/root/mailinabox", "describe", "--always", "--abbrev=0"))
        self.refused(*git, "relative", "describe", "--always", "--abbrev=0")
        self.refused(*git, "/root/mailinabox", "describe", "--dirty")
        self.refused("ss", "-H", "-l", "-n", "-t", "-u", "-K")
        self.refused("find", "/", "-delete")
        self.refused("hostname", "new-name")
        self.refused("sshd", "-T", "-f", "/tmp/evil")
        self.refused("postconf", "-h", "mynetworks\x00x")

    def test_every_rule_documents_its_side_effects_and_limits(self) -> None:
        for rule in RULES:
            self.assertTrue(rule.why.strip(), rule)
            self.assertGreater(rule.timeout, 0, rule)
            self.assertLessEqual(rule.timeout, 900, rule)
            self.assertGreater(rule.max_bytes, 0, rule)
            self.assertNotIn(rule.program, ("sh", "bash", "env", "sudo", "xargs", "python3", "perl"))
        mutating = {(r.program, *(m.value for m in r.args if isinstance(m, Lit))) for r in RULES if r.mutating}
        self.assertEqual(
            mutating,
            {
                ("fail2ban-client", "set", "banip"),
                ("fail2ban-client", "set", "unbanip"),
                ("fail2ban-client", "unban"),
                ("logger", "-t", "mail-sec-audit", "--"),
            },
        )


class SystemRunnerTest(unittest.TestCase):
    def runner(self, *rules: Rule) -> SystemRunner:
        return SystemRunner(Policy(rules=rules))

    def test_missing_program(self) -> None:
        runner = self.runner(Rule("mail-sec-audit-no-such-tool", (), "test"))
        self.assertIs(runner.run(["mail-sec-audit-no-such-tool"]).state, ExecState.MISSING)

    def test_timeout_kills_the_process(self) -> None:
        runner = self.runner(Rule("sleep", (Lit("5"),), "test", timeout=0.3))
        result = runner.run(["sleep", "5"])
        self.assertIs(result.state, ExecState.TIMEOUT)
        self.assertLess(result.duration_ms, 4000)

    def test_output_limit_truncates(self) -> None:
        runner = self.runner(Rule("yes", (), "test", max_bytes=1000, timeout=10))
        result = runner.run(["yes"])
        self.assertIs(result.state, ExecState.TRUNCATED)
        self.assertLessEqual(len(result.stdout), 1000)

    def test_stream_limit_truncates(self) -> None:
        runner = self.runner(Rule("yes", (), "test", max_bytes=100, timeout=10))
        with runner.stream(["yes"]) as handle:
            lines = list(handle.lines)
        self.assertIs(handle.result.state, ExecState.TRUNCATED)
        self.assertLessEqual(sum(len(line) + 1 for line in lines), 100)

    def test_nonzero_and_environment(self) -> None:
        runner = self.runner(Rule("false", (), "test"))
        self.assertIs(runner.run(["false"]).state, ExecState.NONZERO)
        env = child_env()
        self.assertEqual(env["LC_ALL"], "C")
        self.assertTrue(env["PATH"].startswith("/usr/local/sbin"))
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("LD_PRELOAD", env)

    def test_stdin_only_where_allowed(self) -> None:
        runner = self.runner(Rule("cat", (), "test"))
        with self.assertRaises(ForbiddenCommand):
            runner.run(["cat"], input_text="x")

    def test_failure_reasons(self) -> None:
        self.assertEqual(
            failure_reason(R(("ufw",), ExecState.NONZERO, 1, "", "ERROR: You need to be root")), "permission_denied"
        )
        self.assertEqual(failure_reason(R(("x",), ExecState.NONZERO, 2, "", "boom")), "command_failed")
        self.assertEqual(failure_reason(R(("x",), ExecState.TIMEOUT)), "timeout")
        self.assertEqual(failure_reason(R(("x",), ExecState.MISSING)), "missing_tool")


if __name__ == "__main__":
    unittest.main()
