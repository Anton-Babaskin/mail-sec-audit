"""Build the single-file release: dist/mail-sec-audit.pyz.

Usage: python3 tools/build_zipapp.py [output]
The archive contains only the mail_sec_audit package and a __main__ module;
it runs with the system Python 3.9+ and has no dependencies.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import zipapp

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAIN = "from mail_sec_audit.app import main\n\nraise SystemExit(main())\n"


def build(target: pathlib.Path) -> pathlib.Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="msa-build.") as staging:
        stage = pathlib.Path(staging)
        shutil.copytree(
            ROOT / "mail_sec_audit",
            stage / "mail_sec_audit",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (stage / "__main__.py").write_text(MAIN, encoding="utf-8")
        zipapp.create_archive(stage, target, interpreter="/usr/bin/env python3", compressed=True)
    os.chmod(target, 0o755)  # noqa: S103 - the release file is an executable script
    return target


if __name__ == "__main__":
    output = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "mail-sec-audit.pyz"
    print(build(output))
