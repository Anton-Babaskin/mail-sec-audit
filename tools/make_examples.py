"""Regenerate examples/ from the synthetic Mail-in-a-Box test scenario.

Usage: TZ=UTC python3 tools/make_examples.py
The data is the fixture from tests/e2e/test_stacks.py (.example domains,
documentation IP ranges); it is not output from a real server.
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mail_sec_audit.i18n import Translator  # noqa: E402
from mail_sec_audit.render import fleetops, json_v1  # noqa: E402
from mail_sec_audit.render.redact import NO_REDACTION  # noqa: E402
from mail_sec_audit.render.terminal import TextRenderer  # noqa: E402
from mail_sec_audit.rules import SECTIONS  # noqa: E402
from tests.e2e.test_stacks import Prober, miab  # noqa: E402
from tests.helpers import run_scenario  # noqa: E402


def main() -> None:
    files, responses = miab()
    args = ("--domain", "example.org")
    out = ROOT / "examples"
    for lang in ("en", "ru"):
        scenario = run_scenario(files, responses, args=args, prober=Prober(), lang=lang)
        scenario.report.duration_ms = 4210
        text = TextRenderer(Translator(lang), NO_REDACTION, color=False, verbose=False, sections=SECTIONS).render(
            scenario.report
        )
        (out / f"report-mailinabox.{lang}.txt").write_text(text, encoding="utf-8")
    report = run_scenario(files, responses, args=args, prober=Prober()).report
    report.duration_ms = 4210
    (out / "report-mailinabox.json").write_text(
        fleetops.render(report, Translator("en"), NO_REDACTION, redacted=False, durations={}),
        encoding="utf-8",
    )
    (out / "report-mailinabox.v1.json").write_text(
        json_v1.render(report, Translator("en"), NO_REDACTION, redacted=False), encoding="utf-8"
    )
    print("examples written")


if __name__ == "__main__":
    main()
