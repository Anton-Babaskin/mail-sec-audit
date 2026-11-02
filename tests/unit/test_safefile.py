from __future__ import annotations

import os
import stat
import tempfile
import unittest

from mail_sec_audit.safefile import LockBusy, ReportError, open_report, single_instance


class ReportFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="msa-report.")
        self.dir = self.tmp.name

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def test_new_report_is_private(self) -> None:
        old = os.umask(0)
        try:
            target = open_report(self.path("sub/report.txt"), append=False)
        finally:
            os.umask(old)
        target.write("hello\n")
        target.close()
        info = os.stat(self.path("sub/report.txt"))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        with open(self.path("sub/report.txt")) as handle:
            self.assertEqual(handle.read(), "hello\n")

    def test_existing_file_and_symlinks_are_refused(self) -> None:
        open(self.path("existing"), "w").close()
        os.symlink(self.path("existing"), self.path("link"))
        os.symlink(self.path("nowhere"), self.path("dangling"))
        for name, key in (
            ("existing", "report.error.exists"),
            ("link", "report.error.symlink"),
            ("dangling", "report.error.symlink"),
        ):
            with self.subTest(name=name), self.assertRaises(ReportError) as caught:
                open_report(self.path(name), append=False)
            self.assertEqual(caught.exception.key, key)
        self.assertFalse(os.path.exists(self.path("nowhere")))

    def test_append_requires_private_regular_single_link_file(self) -> None:
        good = self.path("good")
        fd = os.open(good, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        target = open_report(good, append=True)
        target.write("x")
        target.close()
        with self.assertRaises(ReportError):
            open_report(self.path("missing"), append=True)
        os.symlink(good, self.path("link"))
        with self.assertRaises(ReportError):
            open_report(self.path("link"), append=True)
        os.link(good, self.path("hardlink"))
        with self.assertRaises(ReportError) as caught:
            open_report(good, append=True)
        self.assertIn("hard links", caught.exception.params["detail"])
        os.unlink(self.path("hardlink"))
        os.chmod(good, 0o666)
        with self.assertRaises(ReportError):
            open_report(good, append=True)
        os.chmod(good, 0o600)
        with self.assertRaises(ReportError):
            open_report(good, append=True, euid=os.geteuid() + 1)
        os.mkfifo(self.path("fifo"), 0o600)
        with self.assertRaises(ReportError):
            open_report(self.path("fifo"), append=True)

    def test_discard_removes_only_the_created_file(self) -> None:
        target = open_report(self.path("partial"), append=False)
        target.discard()
        self.assertFalse(os.path.exists(self.path("partial")))
        target = open_report(self.path("swapped"), append=False)
        os.rename(self.path("swapped"), self.path("moved"))
        open(self.path("swapped"), "w").close()
        target.discard()
        self.assertTrue(os.path.exists(self.path("swapped")))

    def test_lock_is_exclusive(self) -> None:
        lock = self.path("audit.lock")
        with single_instance(lock), self.assertRaises(LockBusy), single_instance(lock):
            pass
        with single_instance(lock):
            pass
        os.symlink(self.path("elsewhere"), self.path("link.lock"))
        with self.assertRaises(LockBusy), single_instance(self.path("link.lock")):
            pass


if __name__ == "__main__":
    unittest.main()
