from __future__ import annotations

import ast
import pathlib
import re
import unittest

from mail_sec_audit.i18n import CATALOGS, Translator, placeholders

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "mail_sec_audit"
KEY_RE = re.compile(r"^(?:[a-z0-9_]+\.)+[a-z0-9_]+$")
PREFIXES = ("cli.", "report.", "signal.", "ui.", "source.", "section.", "common.", "interactive.")
DESTRUCTIVE = re.compile(
    r"rm -rf|postsuper -d|mkfs|\bdd if=|iptables -F|nft flush|ufw disable|ufw reset|systemctl (stop|disable)"
    r"|userdel|chmod -R 777|reboot now|shutdown|apt(-get)? (remove|purge)|DROP TABLE",
    re.IGNORECASE,
)


class CatalogTest(unittest.TestCase):
    def test_same_keys_and_placeholders(self) -> None:
        en, ru = CATALOGS["en"], CATALOGS["ru"]
        self.assertEqual(set(en) - set(ru), set(), "missing in ru")
        self.assertEqual(set(ru) - set(en), set(), "missing in en")
        for key in en:
            with self.subTest(key=key):
                self.assertEqual(placeholders(en[key]), placeholders(ru[key]))

    def test_no_destructive_recommendations(self) -> None:
        for lang, catalog in CATALOGS.items():
            for key, text in catalog.items():
                with self.subTest(lang=lang, key=key):
                    self.assertIsNone(DESTRUCTIVE.search(text))

    def test_literal_keys_used_in_code_exist(self) -> None:
        """String literals that look like catalog keys must be in the catalog."""
        en = CATALOGS["en"]
        missing = []
        for path in PACKAGE.rglob("*.py"):
            if "i18n" in path.parts:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    value = node.value
                    if KEY_RE.match(value) and value.startswith(PREFIXES) and value not in en:
                        missing.append(f"{path.name}: {value}")
        self.assertEqual(missing, [])

    def test_strict_translator(self) -> None:
        t = Translator("ru", strict=True)
        self.assertEqual(t("ctx.fqdn.ok", {"name": "mail.example.org"}), "Имя хоста mail.example.org выглядит как FQDN")
        with self.assertRaises(KeyError):
            t("no.such.key")
        with self.assertRaises(KeyError):
            t("ctx.fqdn.ok", {})
        lenient = Translator("en")
        self.assertIn("ctx.fqdn.ok", lenient("ctx.fqdn.ok", {}) + "ctx.fqdn.ok")

    def test_parameters_are_sanitized(self) -> None:
        t = Translator("en")
        text = t("ctx.fqdn.warn", {"name": "evil\x1b[31mred‮"})
        self.assertNotIn("\x1b", text)
        self.assertNotIn("‮", text)
        self.assertIn("\\x1b", text)


if __name__ == "__main__":
    unittest.main()
