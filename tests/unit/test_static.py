"""Static guarantees about the source tree."""

from __future__ import annotations

import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "mail_sec_audit"


def sources() -> list[pathlib.Path]:
    return sorted(PACKAGE.rglob("*.py"))


class StaticTest(unittest.TestCase):
    def test_processes_only_in_runner(self) -> None:
        offenders = []
        for path in sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names]
                    module = node.module if isinstance(node, ast.ImportFrom) else ""
                    if ("subprocess" in names or module == "subprocess") and path.name != "runner.py":
                        offenders.append(f"{path.name}: imports subprocess")
                if isinstance(node, ast.Call):
                    func = node.func
                    name = (
                        func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                    )
                    if name in ("system", "popen", "spawnl", "spawnv", "execv", "execve", "execvp", "eval", "exec"):
                        offenders.append(f"{path.name}:{node.lineno}: {name}()")
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            offenders.append(f"{path.name}:{node.lineno}: shell=")
        self.assertEqual(offenders, [])

    def test_no_secret_paths_are_read(self) -> None:
        pattern = re.compile(r"mailcow\.conf|sasl_passwd|/etc/shadow|/etc/ssl/private|\.key[\"']|postcat|doveadm")
        offenders = [
            f"{p.name}: {m.group(0)}" for p in sources() for m in pattern.finditer(p.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_rules_do_not_check_stack_names(self) -> None:
        pattern = re.compile(r"[\"'](mailinabox|mailcow|iredmail)[\"']")
        offenders = []
        for path in sorted((PACKAGE / "rules").glob("*.py")):
            for match in pattern.finditer(path.read_text(encoding="utf-8")):
                offenders.append(f"{path.name}: {match.group(0)}")
        self.assertEqual(offenders, [])

    def test_rule_modules_define_one_check(self) -> None:
        from mail_sec_audit.rules import REGISTRY

        ids = [module.CHECK.id for module in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)), "duplicate check id")
        files = {p.stem for p in (PACKAGE / "rules").glob("*.py") if not p.stem.startswith("_")} - {"__init__", "base"}
        registered = {module.__name__.rsplit(".", 1)[-1] for module in REGISTRY}  # type: ignore[attr-defined]
        self.assertEqual(files - registered, set(), "rule module not registered")
        for module in REGISTRY:
            name = module.__name__.rsplit(".", 1)[-1]  # type: ignore[attr-defined]
            self.assertEqual(name, module.CHECK.id.lower().replace(".", "_"), name)

    def test_python39_syntax(self) -> None:
        for path in sources():
            ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
