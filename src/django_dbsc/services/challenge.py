"""Short-lived, one-time challenges that bind each DBSC proof to a moment in time.

The ``scope`` is a DBSC session id, or a pending Django session key during registration.
"""

import secrets
import time

from django.core.cache import cache as default_cache

KEY_PREFIX = "django_dbsc:challenges:"


def registration_scope(session_key: str) -> str:
    # WHY scope by session: a registration proof must only be usable by the login that was offered the challenge.
    return f"register:{session_key}"


def refresh_scope(session_identifier: str) -> str:
    return f"refresh:{session_identifier}"


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
        cutoff = self.clock() - self.ttl
        return [e for e in self.cache.get(KEY_PREFIX + scope, []) if e[1] > cutoff]

    def _save(self, scope: str, entries: list[tuple[str, float]]) -> None:
        self.cache.set(KEY_PREFIX + scope, entries, timeout=self.ttl)
