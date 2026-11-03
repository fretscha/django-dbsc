"""Serialization of DBSC response headers as RFC 9651 structured fields."""

import http_sf

from django_dbsc.services.proof import ALLOWED_ALGS


def registration_header(
    *, path: str, challenge: str, algs: tuple[str, ...] = ("ES256", "RS256"), authorization: str | None = None
) -> str:
    # WHY: never advertise an alg the proof verifier would reject, or the browser would register for nothing.
    unsupported = [alg for alg in algs if alg not in ALLOWED_ALGS]
    if unsupported:
        raise ValueError(f"alg(s) {unsupported} not supported")
    params = {"path": path, "challenge": challenge}
    if authorization is not None:
        params["authorization"] = authorization
    return http_sf.ser([([http_sf.Token(alg) for alg in algs], params)])


def challenge_header(*, challenge: str, session_identifier: str) -> str:
    return http_sf.ser((challenge, {"id": session_identifier}))
