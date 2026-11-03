"""Local TLS probes and certificate parsing.

Probes connect only to addresses of local listeners (127.0.0.1/::1 for
wildcard binds). Every probe is listed in the report. Certificates are
parsed with ``openssl x509`` from stdin; trust is not evaluated.

The legacy-protocol probe offers only TLS 1.0 or 1.1 with ``@SECLEVEL=0``.
When this Python/OpenSSL cannot offer the version at all, the result is
``client_unsupported`` (UNKNOWN), never "the server rejected it" (R-10).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Protocol, Union

from ..runner import Runner
from .base import Unavailable, from_result
from .sockets import Listeners

IMPLICIT = {443: "", 465: "", 993: "", 995: ""}
STARTTLS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3"}
REJECTED_REASONS = frozenset(
    {
        "TLSV1_ALERT_PROTOCOL_VERSION",
        "UNSUPPORTED_PROTOCOL",
        "WRONG_VERSION_NUMBER",
        "SSLV3_ALERT_HANDSHAKE_FAILURE",
        "TLSV1_ALERT_INSUFFICIENT_SECURITY",
        "NO_SHARED_CIPHER",
        "VERSION_TOO_LOW",
    }
)
CLIENT_REASONS = frozenset({"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"})


@dataclass(frozen=True)
class Target:
    port: int
    address: str
    starttls: str

    @property
    def label(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Handshake:
    target: Target
    ok: bool
    protocol: str = ""
    der: bytes = b""
    error: str = ""


class Prober(Protocol):
    def handshake(self, target: Target, server_name: str) -> Handshake: ...

    def legacy(self, target: Target, version: str) -> str: ...


def targets(listeners: Listeners) -> list[Target]:
    found: dict[int, Target] = {}
    for item in listeners.items:
        if item.proto != "tcp" or (item.port not in IMPLICIT and item.port not in STARTTLS):
            continue
        if item.address in ("0.0.0.0", "*"):
            address = "127.0.0.1"
        elif item.address == "::":
            address = "::1"
        else:
            address = item.address
        current = found.get(item.port)
        if current is None or (current.address != "127.0.0.1" and address == "127.0.0.1"):
            found[item.port] = Target(item.port, address, STARTTLS.get(item.port, ""))
    return [found[p] for p in sorted(found)]


def _line(sock: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\n") and len(data) < 4096:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("ascii", "replace")


def _starttls(sock: socket.socket, mode: str) -> None:
    if mode == "smtp":
        line = _line(sock)
        while line[3:4] == "-":
            line = _line(sock)
        if not line.startswith("220"):
            raise OSError(f"no SMTP greeting: {line.strip()[:60]}")
        sock.sendall(b"EHLO mail-sec-audit.invalid\r\n")
        capabilities = []
        line = _line(sock)
        capabilities.append(line)
        while line[3:4] == "-":
            line = _line(sock)
            capabilities.append(line)
        if not any("STARTTLS" in c.upper() for c in capabilities):
            raise OSError("STARTTLS not offered")
        sock.sendall(b"STARTTLS\r\n")
        if not _line(sock).startswith("220"):
            raise OSError("STARTTLS refused")
    elif mode == "imap":
        _line(sock)
        sock.sendall(b"a1 STARTTLS\r\n")
        if not _line(sock).startswith("a1 OK"):
            raise OSError("STARTTLS refused")
    elif mode == "pop3":
        _line(sock)
        sock.sendall(b"STLS\r\n")
        if not _line(sock).startswith("+OK"):
            raise OSError("STLS refused")


class SocketProber:
    timeout = 10.0

    def _connect(self, target: Target) -> socket.socket:
        sock = socket.create_connection((target.address, target.port), timeout=self.timeout)
        try:
            _starttls(sock, target.starttls)
        except Exception:
            sock.close()
            raise
        return sock

    def handshake(self, target: Target, server_name: str) -> Handshake:
        # Verification is off on purpose: the audit must read expired,
        # self-signed or mismatched certificates to report on them. The
        # connection goes to a local listener and carries no data.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            sock = self._connect(target)
        except OSError as exc:
            return Handshake(target, False, error=str(exc)[:120])
        try:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                return Handshake(target, True, tls.version() or "", tls.getpeercert(binary_form=True) or b"")
        except (ssl.SSLError, OSError) as exc:
            return Handshake(target, False, error=getattr(exc, "reason", None) or str(exc)[:120])
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def legacy(self, target: Target, version: str) -> str:
        """``accepted``, ``rejected``, ``client_unsupported`` or ``error:<reason>``."""
        wanted = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}[version]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.minimum_version = wanted
            context.maximum_version = wanted
        except (ValueError, ssl.SSLError):
            return "client_unsupported"
        try:
            sock = self._connect(target)
        except OSError as exc:
            return f"error:{str(exc)[:80]}"
        try:
            with context.wrap_socket(sock) as tls:
                return "accepted" if tls.version() == version else "rejected"
        except ssl.SSLError as exc:
            reason = getattr(exc, "reason", None) or ""
            if reason in CLIENT_REASONS:
                return "client_unsupported"
            if reason in REJECTED_REASONS:
                return "rejected"
            return f"error:{reason or str(exc)[:80]}"
        except OSError as exc:
            return f"error:{str(exc)[:80]}"
        finally:
            with contextlib.suppress(OSError):
                sock.close()


@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    not_after: Optional[dt.datetime]
    name_matches: Optional[bool]
    source: str


def parse_certificate(runner: Runner, der: bytes, name: str) -> Union[Certificate, Unavailable]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    argv = ["openssl", "x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-checkhost", name]
    result = runner.run(argv, input_text=pem)
    if not result.ok:
        return from_result(result)
    fields: dict[str, str] = {}
    match: Optional[bool] = None
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("subject", "issuer", "notBefore", "notAfter"):
            fields[key] = value.strip()
        elif "does match certificate" in line:
            match = True
        elif "does NOT match certificate" in line:
            match = False
    not_after = None
    if "notAfter" in fields:
        with contextlib.suppress(ValueError):
            not_after = dt.datetime.strptime(fields["notAfter"].replace("  ", " "), "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=dt.timezone.utc
            )
    return Certificate(fields.get("subject", ""), fields.get("issuer", ""), not_after, match, f"cmd:{result.display}")
