"""Verification of DBSC proof JWTs (``Secure-Session-Response``).

Freshness comes only from the challenge (``jti``). The spec defines no ``exp``/``iat``/``aud``, so callers must pass
just the short-lived, unconsumed challenges for the session and consume the ``jti`` after a successful verify.
"""

from collections.abc import Container
from dataclasses import dataclass

import jwt

PROOF_TYP = "dbsc+jwt"
# WHY: the spec also allows "none", but an unsigned proof proves nothing about key possession.
ALLOWED_ALGS = frozenset({"ES256", "RS256"})


class ProofError(Exception):
    pass


class UnknownChallengeError(ProofError):
    """The proof is validly signed, but for a challenge that is unknown, expired or already used."""


@dataclass(frozen=True)
class VerifiedProof:
    jti: str
    alg: str
    public_jwk: dict | None
    claims: dict


def verify_registration_proof(
    token: str, *, challenges: Container[str], expected_authorization: str | None = None
) -> VerifiedProof:
    header = _checked_header(token)
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ProofError("registration proof must carry a jwk header")
    claims = _decode(token, jwk, header["alg"], challenges)
    if expected_authorization is not None and claims.get("authorization") != expected_authorization:
        raise ProofError("authorization claim does not match")
    return VerifiedProof(jti=claims["jti"], alg=header["alg"], public_jwk=jwk, claims=claims)


def verify_refresh_proof(token: str, *, challenges: Container[str], public_jwk: dict, alg: str) -> VerifiedProof:
    header = _checked_header(token)
    if "jwk" in header:
        # WHY: the spec says jwk MUST be absent on refresh. Accepting it could let a caller swap in its own key.
        raise ProofError("refresh proof must not carry a jwk header")
    if header["alg"] != alg:
        raise ProofError(f"alg mismatch: session registered with {alg}, proof uses {header['alg']}")
    claims = _decode(token, public_jwk, alg, challenges)
    return VerifiedProof(jti=claims["jti"], alg=alg, public_jwk=None, claims=claims)


def _checked_header(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise ProofError(f"malformed proof: {exc}") from exc
    if header.get("typ") != PROOF_TYP:
        raise ProofError(f"unexpected typ {header.get('typ')!r}")
    if header.get("alg") not in ALLOWED_ALGS:
        raise ProofError(f"alg {header.get('alg')!r} not allowed")
    return header


def _decode(token: str, jwk: dict, alg: str, challenges: Container[str]) -> dict:
    try:
        key = jwt.PyJWK(jwk, algorithm=alg).key
        # WHY: algorithms is pinned to one value we chose, never taken from the token itself.
        claims = jwt.decode(token, key, algorithms=[alg], options={"require": ["jti"], "verify_aud": False})
    except jwt.InvalidSignatureError as exc:
        raise ProofError("invalid signature") from exc
    except (jwt.InvalidTokenError, jwt.PyJWKError) as exc:
        raise ProofError(f"invalid proof: {exc}") from exc
    if claims["jti"] not in challenges:
        raise UnknownChallengeError("unknown or expired challenge")
    return claims
