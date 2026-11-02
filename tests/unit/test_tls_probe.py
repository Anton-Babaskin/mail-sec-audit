"""The real socket prober against local test servers on 127.0.0.1.

The certificate is generated per run with the openssl CLI (skipped when it
is missing); nothing leaves the loopback interface.
"""

from __future__ import annotations

import contextlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from collections.abc import Iterator

from mail_sec_audit.facts.tls import SocketProber, Target


def _readline(conn: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data


@contextlib.contextmanager
def server(context: ssl.SSLContext, *, starttls: bool) -> Iterator[int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(10)
    stop = threading.Event()

    def handle(conn: socket.socket) -> None:
        with conn:
            try:
                if starttls:
                    conn.sendall(b"220 mx1.example.org ESMTP\r\n")
                    _readline(conn)
                    conn.sendall(b"250-mx1.example.org\r\n250 STARTTLS\r\n")
                    _readline(conn)
                    conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    def loop() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)


@unittest.skipIf(shutil.which("openssl") is None, "openssl CLI is needed to create a test certificate")
class SocketProberTest(unittest.TestCase):
    tmp: tempfile.TemporaryDirectory[str]
    cert: str
    key: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="msa-tls.")
        cls.cert = f"{cls.tmp.name}/cert.pem"
        cls.key = f"{cls.tmp.name}/key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                cls.key,
                "-out",
                cls.cert,
                "-days",
                "2",
                "-subj",
                "/CN=mx1.example.org",
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def context(self, minimum: ssl.TLSVersion) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        with contextlib.suppress(ValueError, ssl.SSLError):
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.minimum_version = minimum
        return context

    def test_starttls_handshake_and_modern_server_rejects_tls10(self) -> None:
        prober = SocketProber()
        with server(self.context(ssl.TLSVersion.TLSv1_2), starttls=True) as port:
            target = Target(port, "127.0.0.1", "smtp")
            result = prober.handshake(target, "mx1.example.org")
            self.assertTrue(result.ok, result.error)
            self.assertIn(result.protocol, ("TLSv1.2", "TLSv1.3"))
            self.assertTrue(result.der)
            legacy = prober.legacy(target, "TLSv1")
        self.assertIn(legacy, ("rejected", "client_unsupported"), "never 'accepted' by a TLS 1.2+ server")

    def test_legacy_server_is_not_reported_as_rejected(self) -> None:
        prober = SocketProber()
        with server(self.context(ssl.TLSVersion.TLSv1), starttls=False) as port:
            legacy = prober.legacy(Target(port, "127.0.0.1", ""), "TLSv1")
        # On builds where the client cannot offer TLS 1.0 the result must say so (UNKNOWN), not "rejected".
        self.assertIn(legacy, ("accepted", "client_unsupported"))

    def test_no_starttls(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def plain() -> None:
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"220 x ESMTP\r\n")
                _readline(conn)
                conn.sendall(b"250 x\r\n")
                _readline(conn)

        thread = threading.Thread(target=plain, daemon=True)
        thread.start()
        result = SocketProber().handshake(Target(port, "127.0.0.1", "smtp"), "mx1.example.org")
        listener.close()
        thread.join(timeout=5)
        self.assertFalse(result.ok)
        self.assertIn("STARTTLS", result.error)


if __name__ == "__main__":
    unittest.main()
