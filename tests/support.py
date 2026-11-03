"""Test doubles that play the browser's role in the DBSC protocol."""

import json

import http_sf
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


class DeviceKey:
    """Plays the browser's TPM-backed key: it signs DBSC proofs."""

    def __init__(self, alg: str = "ES256"):
        self.alg = alg
        if alg == "ES256":
            self._private = ec.generate_private_key(ec.SECP256R1())
            self.public_jwk = json.loads(ECAlgorithm.to_jwk(self._private.public_key()))
        elif alg == "RS256":
            self._private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_jwk = json.loads(RSAAlgorithm.to_jwk(self._private.public_key()))
        else:
            raise ValueError(f"unsupported test alg {alg!r}")

    def proof(self, *, jti: str, include_jwk: bool, typ: str = "dbsc+jwt", **claims) -> str:
        headers = {"typ": typ}
        if include_jwk:
            headers["jwk"] = self.public_jwk
        return jwt.encode({"jti": jti, **claims}, self._private, algorithm=self.alg, headers=headers)

    def registration_proof(self, jti: str, **kw) -> str:
        return self.proof(jti=jti, include_jwk=True, **kw)

    def refresh_proof(self, jti: str, **kw) -> str:
        return self.proof(jti=jti, include_jwk=False, **kw)


def unsigned_proof(*, jti: str, jwk: dict | None = None) -> str:
    """An alg=none token. The spec allows it, but this library must refuse it."""
    headers = {"typ": "dbsc+jwt"}
    if jwk is not None:
        headers["jwk"] = jwk
    return jwt.encode({"jti": jti}, None, algorithm="none", headers=headers)


def parse_registration(value: str) -> list[tuple[list[str], dict]]:
    """Parse Secure-Session-Registration the way a browser would: [(algs, params), ...]."""
    entries = http_sf.parse(value.encode(), tltype="list")
    return [([str(alg) for alg, _ in algs], params) for algs, params in entries]


def register_browser(client, device: DeviceKey, *, username: str = "alice", password: str = "pw") -> tuple[str, str]:
    """Log in and complete DBSC registration like a browser would. Returns (session_identifier, refresh_challenge)."""
    login = client.post("/login/", {"username": username, "password": password})
    ((_, params),) = parse_registration(login.headers["Secure-Session-Registration"])
    response = client.post(
        "/dbsc/register", headers={"Secure-Session-Response": device.registration_proof(params["challenge"])}
    )
    assert response.status_code == 200, response.status_code
    challenge, _ = http_sf.parse(response.headers["Secure-Session-Challenge"].encode(), tltype="item")
    return response.json()["session_identifier"], challenge
