"""DBSC registration: offer it after login (step 1), then bind the session to the device key (step 2)."""

from dataclasses import dataclass
from typing import cast

from django_dbsc import conf
from django_dbsc.constants import REGISTRATION_HEADER, RESPONSE_HEADER, SESSION_CHALLENGE_PENDING, SESSION_DBSC_ID
from django_dbsc.repositories import DeviceBoundSessionRepository
from django_dbsc.services.challenge import (
    ChallengeStore,
    refresh_challenges,
    refresh_scope,
    registration_challenges,
    registration_scope,
)
from django_dbsc.services.headers import registration_header
from django_dbsc.services.proof import ProofError, verify_registration_proof

_OFFER_FLAG = "_dbsc_offer_registration"


def request_registration_offer(sender, request, user, **kwargs) -> None:
    """``user_logged_in`` receiver. It only flags the request; the middleware writes the header on the response."""
    if request is not None:
        setattr(request, _OFFER_FLAG, True)


def offer_registration(request, response, challenges: ChallengeStore) -> None:
    if not getattr(request, _OFFER_FLAG, False):
        return
    if request.session.session_key is None:
        request.session.save()
    challenge = challenges.issue(registration_scope(request.session.session_key))
    response.headers[REGISTRATION_HEADER] = registration_header(path=conf.get("REGISTRATION_PATH"), challenge=challenge)


async def aoffer_registration(request, response, challenges: ChallengeStore) -> None:
    if not getattr(request, _OFFER_FLAG, False):
        return
    if request.session.session_key is None:
        await request.session.asave()
    challenge = await challenges.aissue(registration_scope(request.session.session_key))
    response.headers[REGISTRATION_HEADER] = registration_header(path=conf.get("REGISTRATION_PATH"), challenge=challenge)


class RegistrationError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class Registration:
    session_identifier: str
    alg: str
    refresh_challenge: str


class RegistrationService:
    """Step 2 of DBSC: verify the browser's proof and bind the Django session to its device key."""

    def __init__(
        self,
        repo: DeviceBoundSessionRepository | None = None,
        challenges: ChallengeStore | None = None,
        refresh_challenge_store: ChallengeStore | None = None,
    ):
        self.repo = repo or DeviceBoundSessionRepository()
        self.challenges = challenges or registration_challenges()
        self.refresh_challenges = refresh_challenge_store or refresh_challenges()

    def register(self, *, django_session, user, proof_token: str | None) -> Registration:
        if user is None or not user.is_authenticated:
            raise RegistrationError(401, "not authenticated")
        if not proof_token:
            raise RegistrationError(400, f"missing {RESPONSE_HEADER} header")
        scope = registration_scope(django_session.session_key or "")
        try:
            proof = verify_registration_proof(proof_token, challenges=self.challenges.active(scope))
        except ProofError as exc:
            raise RegistrationError(400, f"invalid proof: {exc}") from exc
        if not self.challenges.consume(scope, proof.jti):
            # Another request redeemed the same challenge between our verify and consume calls.
            raise RegistrationError(400, "challenge already used")
        # Unreachable via verify_registration_proof. Checked explicitly because asserts vanish under -O.
        if proof.public_jwk is None:
            raise RegistrationError(400, "proof carries no public key")
        try:
            created = self.repo.create(user=user, public_jwk=proof.public_jwk, alg=proof.alg)
        except ValueError as exc:
            raise RegistrationError(400, str(exc)) from exc

        previous = django_session.get(SESSION_DBSC_ID)
        if previous:
            # WHY: a second login in an already-bound session must not leave the old device key valid.
            self.repo.revoke(previous, reason="replaced")
        # cast: ty has no Django plugin, so it types model fields as Field rather than their value type.
        sid = cast(str, created.session_identifier)
        django_session[SESSION_DBSC_ID] = sid
        django_session[SESSION_CHALLENGE_PENDING] = True
        return Registration(sid, proof.alg, self.refresh_challenges.issue(refresh_scope(sid)))
