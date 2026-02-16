from __future__ import annotations

from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.utils import timezone


SESSION_KEY = "homeglue_reauth_at"
SIGN_SALT = "homeglue-reauth-v1"


def is_session_reauthed(*, session, ttl_seconds: int) -> bool:
    """
    Return True if the session has a recent re-auth timestamp.
    """

    try:
        ts = float(session.get(SESSION_KEY) or 0)
    except Exception:
        ts = 0
    if ts <= 0:
        return False
    now = timezone.now().timestamp()
    return (now - ts) <= float(ttl_seconds)


def mark_session_reauthed(*, session) -> None:
    session[SESSION_KEY] = timezone.now().timestamp()
    session.modified = True


def sign_reauth_token(*, user_id: int) -> str:
    signer = TimestampSigner(salt=SIGN_SALT)
    return signer.sign(str(int(user_id)))


def verify_reauth_token(*, token: str, user_id: int, ttl_seconds: int) -> bool:
    """
    Verify that a token was minted for this user and is not expired.
    """

    if not token:
        return False
    signer = TimestampSigner(salt=SIGN_SALT)
    try:
        raw = signer.unsign(token, max_age=int(ttl_seconds))
    except (BadSignature, SignatureExpired):
        return False
    try:
        return int(raw) == int(user_id)
    except Exception:
        return False

