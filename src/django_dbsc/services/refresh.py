"""DBSC refresh: the browser proves it still holds the device key and gets a fresh bound cookie.

Status codes drive browser behaviour (spec §refresh), so each outcome maps to exactly one:
  200  refreshed
  403  ChallengeRequired: sign this new challenge and retry (the browser retries once)
  401  RefreshError: the browser terminates its DBSC session
  5xx  backend trouble: the browser backs off and keeps the session. Never answer 4xx for these.
"""

import secrets
from dataclasses import dataclass
from typing import cast

from django_dbsc.constants import SESSION_DBSC_ID, SESSION_ID_HEADER
from django_dbsc.repositories import DeviceBoundSessionRepository
from django_dbsc.services.challenge import ChallengeStore, refresh_scope
from django_dbsc.services.proof import ProofError, UnknownChallengeError, verify_refresh_proof


class RefreshError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class ChallengeRequired(Exception):
    """Not an error: control flow for the 403 'sign this challenge and retry' answer."""

    def __init__(self, session_identifier: str, challenge: str, reason: str):
        super().__init__(reason)
        self.session_identifier = session_identifier
        self.challenge = challenge
        self.reason = reason


@dataclass(frozen=True)
class Refreshed:
    session_identifier: str
    next_challenge: str


class RefreshService:
    def __init__(self, repo: DeviceBoundSessionRepository | None = None, challenges: ChallengeStore | None = None):
        self.repo = repo or DeviceBoundSessionRepository()
        self.challenges = challenges or ChallengeStore()

    def refresh(self, *, django_session, user, session_id: str | None, proof_token: str | None) -> Refreshed:
        if not session_id:
            raise RefreshError(400, f"missing {SESSION_ID_HEADER} header")
        sid = self._bound_session_id(django_session, user, session_id)
        record = self.repo.get_active(sid)
        if record is None:
            raise RefreshError(401, "device binding revoked or unknown")
        # cast: ty has no Django plugin, so it types model fields as Field rather than their value type.
        if cast(int, record.user_id) != user.pk:
            raise RefreshError(401, "device binding belongs to another user")

        scope = refresh_scope(sid)
        if not proof_token:
            raise ChallengeRequired(sid, self.challenges.issue(scope), "no proof yet")
        try:
            proof = verify_refresh_proof(
                proof_token,
                challenges=self.challenges.active(scope),
                public_jwk=cast(dict, record.public_jwk),
                alg=cast(str, record.alg),
            )
        except UnknownChallengeError as exc:
            raise ChallengeRequired(sid, self.challenges.issue(scope), str(exc)) from exc
        except ProofError as exc:
            # A valid challenge signed by the wrong key is exactly what a session thief would send.
            raise RefreshError(401, f"invalid proof: {exc}") from exc
        if not self.challenges.consume(scope, proof.jti):
            raise ChallengeRequired(sid, self.challenges.issue(scope), "challenge already used")

        self.repo.mark_refreshed(record)
        return Refreshed(sid, self.challenges.issue(scope))

    @staticmethod
    def _bound_session_id(django_session, user, session_id: str) -> str:
        bound = django_session.get(SESSION_DBSC_ID)
        if not bound or user is None or not user.is_authenticated:
            raise RefreshError(401, "no bound, authenticated Django session")
        # WHY compare against the session: the header is client-chosen, so it must name *this* session's binding.
        if not secrets.compare_digest(session_id.encode(), bound.encode()):
            raise RefreshError(401, "session id does not match the Django session")
        return bound
