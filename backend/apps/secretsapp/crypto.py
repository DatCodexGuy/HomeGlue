from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class HomeGlueCryptoError(RuntimeError):
    pass


def _get_fernet() -> Fernet:
    key = getattr(settings, "HOMEGLUE_FERNET_KEY", "") or ""
    if not key:
        raise HomeGlueCryptoError("HOMEGLUE_FERNET_KEY is not set")
    try:
        # Validate base64
        base64.urlsafe_b64decode(key.encode("utf-8"))
    except Exception as e:
        raise HomeGlueCryptoError("HOMEGLUE_FERNET_KEY is not a valid Fernet key") from e
    return Fernet(key.encode("utf-8"))


def encrypt_str(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    f = _get_fernet()
    token = f.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_str(token: str) -> str:
    if not token:
        return ""
    f = _get_fernet()
    try:
        pt = f.decrypt(token.encode("utf-8"))
    except InvalidToken as e:
        raise HomeGlueCryptoError("Invalid token or wrong HOMEGLUE_FERNET_KEY") from e
    return pt.decode("utf-8")

