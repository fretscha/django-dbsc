import pytest

from django_dbsc.services.proof import (
    ProofError,
    UnknownChallengeError,
    verify_refresh_proof,
    verify_registration_proof,
)
from tests.support import DeviceKey, unsigned_proof


@pytest.fixture(params=["ES256", "RS256"])
def device(request):
    return DeviceKey(request.param)


class TestRegistrationProof:
    def test_valid_proof_returns_public_key_and_alg(self, device):
        token = device.registration_proof("c1")

        proof = verify_registration_proof(token, challenges={"c1"})

        assert proof.jti == "c1"
        assert proof.alg == device.alg
        assert proof.public_jwk == device.public_jwk

    def test_rejects_unknown_challenge(self, device):
        with pytest.raises(ProofError, match="challenge"):
            verify_registration_proof(device.registration_proof("forged"), challenges={"c1"})

    def test_rejects_missing_jwk(self, device):
        with pytest.raises(ProofError, match="jwk"):
            verify_registration_proof(device.refresh_proof("c1"), challenges={"c1"})

    def test_rejects_alg_none(self, device):
        token = unsigned_proof(jti="c1", jwk=device.public_jwk)

        with pytest.raises(ProofError, match="alg"):
            verify_registration_proof(token, challenges={"c1"})

    def test_rejects_wrong_typ(self, device):
        with pytest.raises(ProofError, match="typ"):
            verify_registration_proof(device.registration_proof("c1", typ="JWT"), challenges={"c1"})

    def test_rejects_signature_from_a_different_key_than_the_embedded_jwk(self, device):
        # The attacker signs with their own key but embeds the victim's public key.
        attacker = DeviceKey(device.alg)
        token = attacker.proof(jti="c1", include_jwk=False)
        forged = _swap_header_jwk(token, device.public_jwk)

        with pytest.raises(ProofError, match="signature"):
            verify_registration_proof(forged, challenges={"c1"})

    def test_rejects_garbage(self):
        with pytest.raises(ProofError):
            verify_registration_proof("not.a.jwt", challenges={"c1"})

    def test_authorization_claim_must_match_when_expected(self, device):
        token = device.registration_proof("c1", authorization="other")

        with pytest.raises(ProofError, match="authorization"):
            verify_registration_proof(token, challenges={"c1"}, expected_authorization="code-123")

    def test_authorization_claim_accepted_when_matching(self, device):
        token = device.registration_proof("c1", authorization="code-123")

        proof = verify_registration_proof(token, challenges={"c1"}, expected_authorization="code-123")

        assert proof.jti == "c1"


class TestRefreshProof:
    def test_valid_proof_verifies_against_stored_key(self, device):
        proof = verify_refresh_proof(
            device.refresh_proof("c2"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
        )

        assert proof.jti == "c2"

    def test_rejects_jwk_in_header(self, device):
        # The spec says a jwk MUST be absent on refresh. Its presence suggests key substitution.
        with pytest.raises(ProofError, match="jwk"):
            verify_refresh_proof(
                device.registration_proof("c2"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )

    def test_rejects_proof_signed_by_another_device(self, device):
        thief = DeviceKey(device.alg)

        with pytest.raises(ProofError, match="signature"):
            verify_refresh_proof(
                thief.refresh_proof("c2"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )

    def test_rejects_alg_different_from_registration(self):
        es, rs = DeviceKey("ES256"), DeviceKey("RS256")

        with pytest.raises(ProofError, match="alg"):
            verify_refresh_proof(rs.refresh_proof("c2"), challenges={"c2"}, public_jwk=es.public_jwk, alg="ES256")

    def test_rejects_alg_none(self, device):
        with pytest.raises(ProofError, match="alg"):
            verify_refresh_proof(
                unsigned_proof(jti="c2"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )

    def test_rejects_stale_challenge(self, device):
        with pytest.raises(ProofError, match="challenge"):
            verify_refresh_proof(
                device.refresh_proof("old"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )


def _swap_header_jwk(token: str, jwk: dict) -> str:
    import base64
    import json

    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    header["jwk"] = jwk
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return f"{new_header}.{payload_b64}.{sig_b64}"


class TestErrorKinds:
    """The refresh endpoint answers stale challenges (403, retry) differently from bad keys (401, terminate)."""

    def test_stale_challenge_raises_unknown_challenge_error(self, device):
        with pytest.raises(UnknownChallengeError):
            verify_refresh_proof(
                device.refresh_proof("old"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )

    def test_wrong_key_is_not_reported_as_a_challenge_problem(self, device):
        thief = DeviceKey(device.alg)

        with pytest.raises(ProofError) as excinfo:
            verify_refresh_proof(
                thief.refresh_proof("c2"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )
        assert not isinstance(excinfo.value, UnknownChallengeError)

    def test_challenge_is_only_checked_after_signature(self, device):
        # WHY: otherwise a forged token with a stale jti would earn a fresh challenge (403) rather than a 401.
        thief = DeviceKey(device.alg)

        with pytest.raises(ProofError) as excinfo:
            verify_refresh_proof(
                thief.refresh_proof("old"), challenges={"c2"}, public_jwk=device.public_jwk, alg=device.alg
            )
        assert not isinstance(excinfo.value, UnknownChallengeError)
