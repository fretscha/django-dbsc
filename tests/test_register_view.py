from http.cookies import SimpleCookie

import http_sf
import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from django_dbsc.middleware import BOUND_COOKIE_NAME, SESSION_DBSC_ID
from django_dbsc.models import DeviceBoundSession
from django_dbsc.services.challenge import ChallengeStore, refresh_scope, registration_scope
from django_dbsc.services.cookie import BoundCookieCodec
from tests.support import DeviceKey, parse_registration, unsigned_proof

pytestmark = pytest.mark.django_db

URL = "/dbsc/register"


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


@pytest.fixture
def device():
    return DeviceKey("ES256")


@pytest.fixture
def challenge(client, alice):
    """Log in like a browser would, and return the registration challenge we were offered."""
    response = client.post("/login/", {"username": "alice", "password": "pw"})
    ((_, params),) = parse_registration(response.headers["Secure-Session-Registration"])
    return params["challenge"]


def _register(client, token: str | None, **headers):
    if token is not None:
        headers["Secure-Session-Response"] = token
    return client.post(URL, headers=headers)


class TestSuccessfulRegistration:
    def test_binds_session_to_device_key(self, client, alice, device, challenge):
        response = _register(client, device.registration_proof(challenge))

        assert response.status_code == 200
        sid = response.json()["session_identifier"]
        stored = DeviceBoundSession.objects.get(session_identifier=sid)
        assert stored.user == alice
        assert stored.public_jwk == device.public_jwk
        assert client.session[SESSION_DBSC_ID] == sid

    def test_sets_a_valid_bound_cookie(self, client, device, challenge):
        response = _register(client, device.registration_proof(challenge))

        sid = response.json()["session_identifier"]
        assert BoundCookieCodec().is_valid(response.cookies[BOUND_COOKIE_NAME].value, sid)

    def test_protected_pages_work_afterwards(self, client, device, challenge):
        _register(client, device.registration_proof(challenge))

        assert client.get("/protected/").status_code == 200

    def test_returns_session_instructions(self, client, device, challenge):
        body = _register(client, device.registration_proof(challenge)).json()

        assert body["refresh_url"] == "/dbsc/refresh"
        assert body["scope"]["include_site"] is False
        assert body["credentials"] == [
            {"type": "cookie", "name": BOUND_COOKIE_NAME, "attributes": body["credentials"][0]["attributes"]}
        ]
        excluded = {rule["path"] for rule in body["scope"]["scope_specification"] if rule["type"] == "exclude"}
        assert "/static/" in excluded

    def test_declared_cookie_attributes_match_set_cookie(self, client, device, challenge):
        # If these drift apart, the browser thinks the cookie is missing and refreshes in a loop.
        response = _register(client, device.registration_proof(challenge))

        declared = response.json()["credentials"][0]["attributes"]
        parsed = SimpleCookie(f"x=y; {declared}")["x"]
        actual = response.cookies[BOUND_COOKIE_NAME]
        for attr in ("path", "domain", "samesite"):
            assert (parsed[attr] or "").lower() == (actual[attr] or "").lower(), attr
        for flag in ("secure", "httponly"):
            assert bool(parsed[flag]) == bool(actual[flag]), flag
        assert "partitioned" not in declared.lower()

    def test_hands_out_first_refresh_challenge(self, client, device, challenge):
        response = _register(client, device.registration_proof(challenge))

        sid = response.json()["session_identifier"]
        value, params = http_sf.parse(response.headers["Secure-Session-Challenge"].encode(), tltype="item")
        assert params["id"] == sid
        assert value in ChallengeStore().active(refresh_scope(sid))

    def test_response_is_not_cacheable(self, client, device, challenge):
        response = _register(client, device.registration_proof(challenge))

        assert "no-store" in response.headers["Cache-Control"]

    def test_works_without_csrf_token(self, alice, device):
        # The browser makes this POST itself and has no CSRF token. The proof of possession is the anti-forgery check.
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(alice)
        token = device.registration_proof(ChallengeStore().issue(registration_scope(browser.session.session_key)))

        assert _register(browser, token).status_code == 200

    def test_re_registration_revokes_previous_binding(self, client, alice, device, challenge):
        first = _register(client, device.registration_proof(challenge)).json()["session_identifier"]
        second_challenge = ChallengeStore().issue(registration_scope(client.session.session_key))

        second = _register(client, DeviceKey().registration_proof(second_challenge)).json()["session_identifier"]

        assert DeviceBoundSession.objects.get(session_identifier=first).revoked_at is not None
        assert client.session[SESSION_DBSC_ID] == second


class TestRejectedRegistration:
    def test_anonymous_is_rejected(self, client, device):
        assert _register(client, device.registration_proof("c")).status_code == 401

    def test_missing_proof_is_rejected(self, client, challenge):
        assert _register(client, None).status_code == 400

    def test_alg_none_is_rejected(self, client, device, challenge):
        response = _register(client, unsigned_proof(jti=challenge, jwk=device.public_jwk))

        assert response.status_code == 400
        assert not DeviceBoundSession.objects.exists()

    def test_challenge_cannot_be_replayed(self, client, device, challenge):
        token = device.registration_proof(challenge)
        _register(client, token)

        assert _register(client, token).status_code == 400
        assert DeviceBoundSession.objects.count() == 1

    def test_challenge_from_another_session_is_rejected(self, client, device, challenge):
        foreign = ChallengeStore().issue(registration_scope("someone-elses-session"))

        assert _register(client, device.registration_proof(foreign)).status_code == 400

    def test_cross_site_request_is_rejected(self, client, device, challenge):
        response = _register(client, device.registration_proof(challenge), **{"Sec-Fetch-Site": "cross-site"})

        assert response.status_code == 403

    def test_get_is_not_allowed(self, client, challenge):
        assert client.get(URL).status_code == 405

    def test_rejection_does_not_bind_the_session(self, client, device, challenge):
        _register(client, device.registration_proof("wrong-challenge"))

        assert SESSION_DBSC_ID not in client.session
