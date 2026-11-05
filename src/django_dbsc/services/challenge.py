"""Short-lived, one-time challenges that bind each DBSC proof to a moment in time.

The ``scope`` is a DBSC session id, or a pending Django session key during registration.
"""

import secrets
import time

from django.core.cache import cache as default_cache

from django_dbsc import conf

KEY_PREFIX = "django_dbsc:challenges:"

# The browser redeems a registration challenge within milliseconds of the login response.
REGISTRATION_CHALLENGE_TTL = 120
# WHY margin over the cookie lifetime: Chrome caches the challenge from our last response and signs it at the next
# refresh, ~BOUND_COOKIE_MAX_AGE later. A shorter TTL turns every real refresh into a 403 retry round trip.
REFRESH_CHALLENGE_TTL_MARGIN = 60


def registration_scope(session_key: str) -> str:
    # WHY scope by session: a registration proof must only be usable by the login that was offered the challenge.
    return f"register:{session_key}"


def refresh_scope(session_identifier: str) -> str:
    return f"refresh:{session_identifier}"


def registration_challenges() -> "ChallengeStore":
    return ChallengeStore(ttl=REGISTRATION_CHALLENGE_TTL)


def refresh_challenges() -> "ChallengeStore":
    ttl = conf.get("REFRESH_CHALLENGE_TTL") or conf.get("BOUND_COOKIE_MAX_AGE") + REFRESH_CHALLENGE_TTL_MARGIN
    return ChallengeStore(ttl=ttl)


class ChallengeStore:
    def __init__(self, cache=None, ttl: int = 120, keep: int = 3, clock=None):
        self.cache = cache or default_cache
        self.ttl = ttl
        # WHY keep > 1: a proof signed for an older challenge can arrive after a newer one was issued.
        self.keep = keep
        self.clock = clock or time.time

    def issue(self, scope: str) -> str:
        challenge = secrets.token_urlsafe(32)
        entries = self._fresh(scope)
        entries.append((challenge, self.clock()))
        self._save(scope, entries[-self.keep :])
        return challenge

    async def aissue(self, scope: str) -> str:
        challenge = secrets.token_urlsafe(32)
        entries = self._filter_fresh(await self.cache.aget(KEY_PREFIX + scope, []))
        entries.append((challenge, self.clock()))
        await self.cache.aset(KEY_PREFIX + scope, entries[-self.keep :], timeout=self.ttl)
        return challenge

    def active(self, scope: str) -> set[str]:
        return {challenge for challenge, _ in self._fresh(scope)}

    def consume(self, scope: str, challenge: str) -> bool:
        # NOTE: get-then-set is not atomic, so two concurrent refreshes could both consume the same challenge.
        # That's acceptable because each proof still needs the device's private key.
        entries = self._fresh(scope)
        # WHY bytes: compare_digest raises TypeError on non-ASCII str, and the challenge comes from the client.
        candidate = challenge.encode()
        remaining = [e for e in entries if not secrets.compare_digest(e[0].encode(), candidate)]
        if len(remaining) == len(entries):
            return False
        self._save(scope, remaining)
        return True

    def _fresh(self, scope: str) -> list[tuple[str, float]]:
        return self._filter_fresh(self.cache.get(KEY_PREFIX + scope, []))

    def _filter_fresh(self, entries: list[tuple[str, float]]) -> list[tuple[str, float]]:
        cutoff = self.clock() - self.ttl
        return [e for e in entries if e[1] > cutoff]

    def _save(self, scope: str, entries: list[tuple[str, float]]) -> None:
        self.cache.set(KEY_PREFIX + scope, entries, timeout=self.ttl)
