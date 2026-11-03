import http_sf
import pytest
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client

from django_dbsc.api import views
from django_dbsc.constants import BOUND_COOKIE_NAME, SESSION_DBSC_ID
from django_dbsc.models import DeviceBoundSession
from django_dbsc.repositories import DeviceBoundSessionRepository
from django_dbsc.services.challenge import ChallengeStore, refresh_scope
from django_dbsc.services.cookie import BoundCookieCodec
from django_dbsc.services.refresh import RefreshService
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db

URL = "/dbsc/refresh"


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


@pytest.fixture
def device():
    return DeviceKey("ES256")


@pytest.fixture
def bound(client, alice, device):
    """A browser that has logged in and bound its session. Returns (sid, refresh_challenge)."""
    return register_browser(client, device)


def _refresh(client, sid: str | None, token: str | None = None, **headers):
    if sid is not None:
        headers["Sec-Secure-Session-Id"] = sid
    if token is not None:
        headers["Secure-Session-Response"] = token
    return client.post(URL, headers=headers)


def _challenge(response) -> tuple[str, dict]:
    return http_sf.parse(response.headers["Secure-Session-Challenge"].encode(), tltype="item")


class TestSuccessfulRefresh:
    def test_valid_proof_issues_fresh_bound_cookie(self, client, device, bound):
        sid, challenge = bound

        response = _refresh(client, sid, device.refresh_proof(challenge))

        assert response.status_code == 200
        assert BoundCookieCodec().is_valid(response.cookies[BOUND_COOKIE_NAME].value, sid)
        assert response.json()["session_identifier"] == sid

    def test_restores_access_after_bound_cookie_expired(self, client, device, bound):
        sid, challenge = bound
        del client.cookies[BOUND_COOKIE_NAME]  # What the browser sees once Max-Age has elapsed.

        _refresh(client, sid, device.refresh_proof(challenge))

        assert client.get("/protected/").status_code == 200

    def test_hands_out_next_challenge(self, client, device, bound):
        sid, challenge = bound

        response = _refresh(client, sid, device.refresh_proof(challenge))

        next_challenge, params = _challenge(response)
        assert params["id"] == sid
        assert next_challenge != challenge
        assert next_challenge in ChallengeStore().active(refresh_scope(sid))

    def test_records_refresh_time(self, client, device, bound):
        sid, challenge = bound

        _refresh(client, sid, device.refresh_proof(challenge))

        assert DeviceBoundSession.objects.get(session_identifier=sid).last_refreshed_at is not None

    def test_accepts_slightly_older_challenge(self, client, device, bound):
        # Latency race: the browser signed the previous challenge while a newer one was already issued.
        sid, older = bound
        ChallengeStore().issue(refresh_scope(sid))

        assert _refresh(client, sid, device.refresh_proof(older)).status_code == 200

    def test_response_is_hardened(self, client, device, bound):
        sid, challenge = bound

        response = _refresh(client, sid, device.refresh_proof(challenge))

        assert "no-store" in response.headers["Cache-Control"]
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Access-Control-Allow-Credentials" not in response.headers

    def test_works_without_csrf_token(self, alice, device):
        browser = Client(enforce_csrf_checks=True)
        # Logging in and registering are covered elsewhere. Here only refresh must skip CSRF.
        sid, challenge = register_browser(browser, device)

        assert _refresh(browser, sid, device.refresh_proof(challenge)).status_code == 200


class TestChallengeRoundTrip:
    """403 means: here is a fresh challenge, sign it and retry. The browser retries once."""

    def test_missing_proof_gets_403_with_challenge_then_succeeds(self, client, device, bound):
        sid, _ = bound

        first = _refresh(client, sid)
        assert first.status_code == 403
        challenge, params = _challenge(first)
        assert params["id"] == sid

        assert _refresh(client, sid, device.refresh_proof(challenge)).status_code == 200

    def test_unknown_challenge_gets_403_with_new_challenge(self, client, device, bound):
        sid, _ = bound

        response = _refresh(client, sid, device.refresh_proof("never-issued"))

        assert response.status_code == 403
        assert _challenge(response)[0] in ChallengeStore().active(refresh_scope(sid))

    def test_replayed_proof_gets_403(self, client, device, bound):
        sid, challenge = bound
        token = device.refresh_proof(challenge)
        _refresh(client, sid, token)

        assert _refresh(client, sid, token).status_code == 403


class TestTermination:
    """Any 4xx other than 403, 407 or 429 makes the browser drop its DBSC session. We answer 401."""

    def test_logged_out_django_session(self, client, device, bound):
        sid, challenge = bound
        client.logout()

        assert _refresh(client, sid, device.refresh_proof(challenge)).status_code == 401

    def test_revoked_device(self, client, device, bound):
        sid, challenge = bound
        DeviceBoundSessionRepository().revoke(sid)

        assert _refresh(client, sid, device.refresh_proof(challenge)).status_code == 401

    def test_session_id_header_does_not_match_django_session(self, client, device, bound):
        _, challenge = bound

        assert _refresh(client, "other-sid", device.refresh_proof(challenge)).status_code == 401

    def test_proof_signed_by_another_key(self, client, device, bound):
        # Stolen sessionid plus a validly fetched challenge still isn't enough without the device key.
        sid, challenge = bound

        assert _refresh(client, sid, DeviceKey().refresh_proof(challenge)).status_code == 401

    def test_binding_belongs_to_another_user(self, client, device, bound):
        sid, challenge = bound
        bob = get_user_model().objects.create_user("bob", password="pw")
        DeviceBoundSession.objects.filter(session_identifier=sid).update(user=bob)

        assert _refresh(client, sid, device.refresh_proof(challenge)).status_code == 401

    def test_termination_hands_out_no_challenge(self, client, device, bound):
        sid, challenge = bound
        DeviceBoundSessionRepository().revoke(sid)

        assert "Secure-Session-Challenge" not in _refresh(client, sid, device.refresh_proof(challenge)).headers


class TestOtherResponses:
    def test_missing_session_id_header(self, client, device, bound):
        _, challenge = bound

        assert _refresh(client, None, device.refresh_proof(challenge)).status_code == 400

    def test_get_is_not_allowed(self, client, bound):
        assert client.get(URL).status_code == 405

    def test_cross_site_request_is_refused_without_a_challenge(self, client, device, bound):
        sid, _ = bound

        response = _refresh(client, sid, **{"Sec-Fetch-Site": "cross-site"})

        assert response.status_code == 403
        assert "Secure-Session-Challenge" not in response.headers

    def test_backend_failure_is_5xx_not_4xx(self, client, device, bound, monkeypatch):
        # WHY: a 4xx would make the browser terminate the session, logging the user out over a DB hiccup.
        sid, challenge = bound

        class BrokenRepo(DeviceBoundSessionRepository):
            def get_active(self, session_identifier):
                raise DatabaseError("connection lost")

        monkeypatch.setattr(views, "get_refresh_service", lambda: RefreshService(repo=BrokenRepo()))

        assert _refresh(client, sid, device.refresh_proof(challenge)).status_code == 503

    def test_django_session_stays_bound_on_retryable_failure(self, client, device, bound):
        sid, _ = bound

        _refresh(client, sid)

        assert client.session[SESSION_DBSC_ID] == sid
