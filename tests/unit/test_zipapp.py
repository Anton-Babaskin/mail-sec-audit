from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

from mail_sec_audit import __version__
from tools.build_zipapp import build


class ZipappTest(unittest.TestCase):
    def test_archive_runs_in_isolated_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="msa-zip.") as tmp:
            target = build(pathlib.Path(tmp) / "mail-sec-audit.pyz")
            for args, expected in (
                (["--version"], f"mail-sec-audit {__version__}"),
                (["--lang", "ru", "--help"], "--days"),
            ):
                result = subprocess.run(
                    [sys.executable, "-I", str(target), *args],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                    cwd=tmp,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
            bad = subprocess.run(
                [sys.executable, "-I", str(target), "--days", "0"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(bad.returncode, 64)


if __name__ == "__main__":
    unittest.main()
