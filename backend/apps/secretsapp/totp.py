from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


class TotpError(ValueError):
    pass


ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def normalize_base32_secret(secret_b32: str) -> str:
    """
    Normalize a user-provided Base32 secret:
    - strip whitespace/hyphens
    - uppercase
    - remove padding
    """

    s = (secret_b32 or "").strip().replace(" ", "").replace("-", "").upper()
    s = s.rstrip("=")
    if not s:
        raise TotpError("Missing secret.")
    for ch in s:
        if ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567":
            raise TotpError("Invalid Base32 secret.")
    return s


def _b32decode(secret_b32: str) -> bytes:
    s = normalize_base32_secret(secret_b32)
    pad_len = (-len(s)) % 8
    s_padded = s + ("=" * pad_len)
    try:
        return base64.b32decode(s_padded.encode("ascii"), casefold=True)
    except Exception as e:
        raise TotpError("Invalid Base32 secret.") from e


def generate_base32_secret(*, nbytes: int = 20) -> str:
    raw = secrets.token_bytes(int(nbytes))
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def hotp(*, secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    algo = (algorithm or "SHA1").upper()
    if algo not in ALGORITHMS:
        raise TotpError(f"Unsupported algorithm: {algo}")
    if digits < 6 or digits > 10:
        raise TotpError("digits must be between 6 and 10")

    msg = struct.pack(">Q", int(counter))
    h = hmac.new(secret, msg, ALGORITHMS[algo]).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(int(digits))


def totp(*, secret_b32: str, now: int | None = None, digits: int = 6, period: int = 30, algorithm: str = "SHA1") -> tuple[str, int]:
    """
    Return (code, remaining_seconds_in_period).
    """

    if period <= 0:
        raise TotpError("period must be > 0")
    ts = int(time.time() if now is None else int(now))
    counter = ts // int(period)
    secret = _b32decode(secret_b32)
    code = hotp(secret=secret, counter=counter, digits=digits, algorithm=algorithm)
    remaining = int(period) - (ts % int(period))
    if remaining == int(period):
        remaining = 0
    return code, remaining


def build_otpauth_url(
    *,
    issuer: str,
    account_name: str,
    secret_b32: str,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    algo = (algorithm or "SHA1").upper()
    secret_norm = normalize_base32_secret(secret_b32)
    iss = (issuer or "HomeGlue").strip()
    acct = (account_name or "").strip() or "account"
    label = quote(f"{iss}:{acct}")
    qs = (
        f"secret={quote(secret_norm)}"
        f"&issuer={quote(iss)}"
        f"&algorithm={quote(algo)}"
        f"&digits={int(digits)}"
        f"&period={int(period)}"
    )
    return f"otpauth://totp/{label}?{qs}"

