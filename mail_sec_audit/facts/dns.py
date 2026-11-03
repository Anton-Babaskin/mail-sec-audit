"""DNS lookups with ``dig``, keeping the response code.

``dig +short`` hides SERVFAIL and timeouts; here NOERROR without data and
NXDOMAIN mean "absent", SERVFAIL, REFUSED and timeouts mean UNKNOWN.
TXT character-strings are joined without separators (RFC 7208 3.3).
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional, Union

from ..runner import Runner
from .base import Unavailable, from_result

STATUS_RE = re.compile(r"status: ([A-Z]+)")


@dataclass(frozen=True)
class Answer:
    rtype: str
    name: str
    rcode: str
    records: tuple[str, ...]
    source: str

    @property
    def absent(self) -> bool:
        return self.rcode == "NXDOMAIN" or (self.rcode == "NOERROR" and not self.records)


def _txt(rdata: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rdata)
    return "".join(parts) if parts else rdata


def query(runner: Runner, rtype: str, name: str) -> Union[Answer, Unavailable]:
    argv = ["dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer"]
    argv += ["-x", name] if rtype == "PTR" else [rtype, name]
    result = runner.run(argv)
    source = f"dns:{rtype} {name}"
    if not result.ok:
        failure = from_result(result)
        if "timed out" in result.stdout or "no servers could be reached" in result.stdout:
            return Unavailable("timeout", source)
        return Unavailable(failure.reason, source, failure.detail, "dig")
    status = STATUS_RE.search(result.stdout)
    if not status:
        return Unavailable("parse_error", source)
    rcode = status.group(1)
    if rcode not in ("NOERROR", "NXDOMAIN"):
        return Unavailable("command_failed", source, f"DNS status {rcode}", "dig")
    records = []
    for line in result.stdout.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) == 5 and fields[3] == rtype:
            records.append(_txt(fields[4]) if rtype == "TXT" else fields[4].rstrip("."))
    return Answer(rtype, name, rcode, tuple(records), source)


def _der_length(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    if first < 0x80:
        return first, i + 1
    count = first & 0x7F
    return int.from_bytes(data[i + 1 : i + 1 + count], "big"), i + 1 + count


def _der_items(data: bytes) -> list[tuple[int, bytes]]:
    items, i = [], 0
    while i < len(data):
        tag = data[i]
        length, start = _der_length(data, i + 1)
        items.append((tag, data[start : start + length]))
        i = start + length
    return items


RSA_OID = bytes.fromhex("2a864886f70d010101")


def dkim_key(record: str) -> tuple[str, Optional[int]]:
    """Return (algorithm, RSA bits) for a DKIM TXT record; ("revoked", None) for empty p=."""
    tags = {k.strip(): v.strip() for k, _, v in (p.partition("=") for p in record.split(";")) if k.strip()}
    key = re.sub(r"\s+", "", tags.get("p", ""))
    if not key:
        return "revoked", None
    if tags.get("k", "rsa").lower() == "ed25519":
        return "ed25519", None
    try:
        der = base64.b64decode(key, validate=True)
        spki = _der_items(_der_items(der)[0][1])
        algorithm = _der_items(spki[0][1])[0][1]
        if algorithm != RSA_OID:
            return "unknown", None
        bitstring = spki[1][1][1:]
        modulus = _der_items(_der_items(bitstring)[0][1])[0][1].lstrip(b"\x00")
        return "rsa", len(modulus) * 8 - (8 - modulus[0].bit_length())
    except (binascii.Error, ValueError, IndexError):
        return "unknown", None
