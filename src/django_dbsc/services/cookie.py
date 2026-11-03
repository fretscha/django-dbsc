"""The short-lived "bound" cookie that only the device key can renew.

It is signed and stateless, so the middleware's hot path needs no DB or cache lookup.
"""

import time

from django.core import signing

from django_dbsc.constants import BOUND_COOKIE_NAME

SALT = "django_dbsc.bound_cookie"

# WHY one source of truth: the browser matches the Set-Cookie against the attributes declared in the session
# instructions. Any drift between the two makes it think the cookie is missing, and it refreshes in a loop.
# No Partitioned: the spec rejects partitioned bound cookies.
COOKIE_ATTRIBUTES = {"path": "/", "secure": True, "httponly": True, "samesite": "Lax"}


def declared_attributes() -> str:
    """COOKIE_ATTRIBUTES rendered the way a Set-Cookie line spells them."""
    parts = [f"Path={COOKIE_ATTRIBUTES['path']}"]
    if COOKIE_ATTRIBUTES["secure"]:
        parts.append("Secure")
    if COOKIE_ATTRIBUTES["httponly"]:
        parts.append("HttpOnly")
    parts.append(f"SameSite={COOKIE_ATTRIBUTES['samesite']}")
    return "; ".join(parts)


def set_bound_cookie(response, value: str, max_age: int) -> None:
    response.set_cookie(BOUND_COOKIE_NAME, value, max_age=max_age, **COOKIE_ATTRIBUTES)


class BoundCookieCodec:
    def __init__(self, max_age: int = 600, clock=None):
        self.max_age = max_age
        self.clock = clock or time.time
        self._signer = signing.Signer(salt=SALT)

    def encode(self, dbsc_id: str) -> str:
        return self._signer.sign_object({"d": dbsc_id, "t": int(self.clock())}, compress=False)

    def is_valid(self, value: str | None, dbsc_id: str) -> bool:
        if not value:
            return False
        try:
            payload = self._signer.unsign_object(value)
        except (signing.BadSignature, ValueError):
            return False
        if not isinstance(payload, dict) or payload.get("d") != dbsc_id:
            return False
        issued_at = payload.get("t")
        return isinstance(issued_at, int) and 0 <= self.clock() - issued_at <= self.max_age
