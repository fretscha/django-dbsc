"""The middleware and decorator must work natively under ASGI.

Every request goes through AsyncClient with database-backed sessions. In an async context Django raises
SynchronousOnlyOperation for any synchronous DB access (session load, request.user, ORM), so a sync call left in the
async path fails these tests instead of silently blocking the event loop.
"""

import time
from inspect import iscoroutinefunction

import http_sf
import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import AsyncClient

from django_dbsc.constants import BOUND_COOKIE_NAME, SESSION_BINDING_REQUIRED_SINCE, SESSION_DBSC_ID
from django_dbsc.decorators import device_bound_required
from django_dbsc.middleware import DeviceBoundSessionMiddleware
from django_dbsc.models import DeviceBoundSession
from django_dbsc.services.challenge import ChallengeStore, refresh_scope, registration_scope
from tests.support import DeviceKey, parse_registration

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def db_sessions(settings):
    settings.SESSION_ENGINE = "django.contrib.sessions.backends.db"


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


@pytest.fixture
def client():
    return AsyncClient()


def get(client, path, **headers):
    return async_to_sync(client.get)(path, headers=headers)


def post(client, path, data=None, **headers):
    return async_to_sync(client.post)(path, data or {}, headers=headers)


def session(client):
    return async_to_sync(client.asession)()


def register(client, device):
    """Log in through the async login view and complete DBSC registration. Returns (sid, refresh_challenge)."""
    login = post(client, "/async/login/", {"username": "alice", "password": "pw"})
    ((_, params),) = parse_registration(login.headers["Secure-Session-Registration"])
    response = post(
        client, "/dbsc/register", **{"Secure-Session-Response": device.registration_proof(params["challenge"])}
    )
    assert response.status_code == 200, response.status_code
    challenge, _ = http_sf.parse(response.headers["Secure-Session-Challenge"].encode(), tltype="item")
    return response.json()["session_identifier"], challenge


class TestAsyncCapability:
    def test_middleware_declares_both_modes(self):
        assert DeviceBoundSessionMiddleware.sync_capable
        assert DeviceBoundSessionMiddleware.async_capable

    def test_middleware_is_a_coroutine_in_an_async_stack(self):
        async def get_response(request):
            return HttpResponse()

        assert iscoroutinefunction(DeviceBoundSessionMiddleware(get_response))

    def test_middleware_stays_sync_in_a_sync_stack(self):
        assert not iscoroutinefunction(DeviceBoundSessionMiddleware(lambda request: HttpResponse()))

    def test_decorator_keeps_async_views_async(self):
        @device_bound_required
        async def view(request):
            return HttpResponse()

        assert iscoroutinefunction(view)


class TestAsyncEnforcement:
    def test_unbound_session_passes(self, client, alice):
        post(client, "/async/login/", {"username": "alice", "password": "pw"})

        assert get(client, "/async/bound-status/").content == b"False"

    def test_login_offers_registration_with_session_scoped_challenge(self, client, alice):
        response = post(client, "/async/login/", {"username": "alice", "password": "pw"})

        ((_, params),) = parse_registration(response.headers["Secure-Session-Registration"])
        assert params["challenge"] in ChallengeStore().active(registration_scope(session(client).session_key))

    def test_bound_session_with_cookie_is_bound(self, client, alice):
        register(client, DeviceKey())

        assert get(client, "/async/bound-status/").content == b"True"

    def test_first_bound_response_carries_refresh_challenge(self, client, alice):
        sid, _ = register(client, DeviceKey())

        response = get(client, "/async/bound-status/")

        challenge, params = http_sf.parse(response.headers["Secure-Session-Challenge"].encode(), tltype="item")
        assert params["id"] == sid
        assert challenge in ChallengeStore().active(refresh_scope(sid))

    def test_missing_bound_cookie_is_rejected_flushed_and_revoked(self, client, alice):
        sid, _ = register(client, DeviceKey())
        del client.cookies[BOUND_COOKIE_NAME]

        assert get(client, "/async/bound-status/").status_code == 401
        assert SESSION_DBSC_ID not in session(client)
        assert DeviceBoundSession.objects.get(session_identifier=sid).revoked_reason == "missing_bound_cookie"

    def test_skipped_refresh_is_refused_but_keeps_session(self, client, alice):
        sid, _ = register(client, DeviceKey())
        del client.cookies[BOUND_COOKIE_NAME]

        response = get(
            client, "/async/bound-status/", **{"Secure-Session-Skipped": f'quota_exceeded;session_identifier="{sid}"'}
        )

        assert response.status_code == 401
        assert session(client)[SESSION_DBSC_ID] == sid

    def test_logout_revokes_binding(self, client, alice):
        sid, _ = register(client, DeviceKey())

        post(client, "/async/logout/")

        assert DeviceBoundSession.objects.get(session_identifier=sid).revoked_reason == "logout"


class TestAsyncDecorator:
    def test_unbound_is_refused(self, client, alice):
        post(client, "/async/login/", {"username": "alice", "password": "pw"})

        assert get(client, "/async/sensitive/").status_code == 403

    def test_bound_reaches_the_view(self, client, alice):
        register(client, DeviceKey())

        assert get(client, "/async/sensitive/").content == b"sensitive"


class TestAsyncPolicy:
    @pytest.fixture(autouse=True)
    def staff_must_bind(self, settings):
        settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "REQUIRE_BINDING": "django_dbsc.policies.staff_only"}

    @pytest.fixture
    def staff(self):
        return get_user_model().objects.create_user("bob", password="pw", is_staff=True)

    def _login_staff(self, client):
        post(client, "/async/login/", {"username": "bob", "password": "pw"})

    def _expire_grace(self, client):
        s = session(client)
        s[SESSION_BINDING_REQUIRED_SINCE] = int(time.time()) - 31
        async_to_sync(s.asave)()

    def test_staff_may_browse_during_grace(self, client, staff):
        self._login_staff(client)

        assert get(client, "/async/bound-status/").status_code == 200

    def test_staff_unbound_after_grace_is_logged_out(self, client, staff):
        self._login_staff(client)
        get(client, "/async/bound-status/")
        self._expire_grace(client)

        response = get(client, "/async/bound-status/")

        assert response.status_code == 403
        assert "_auth_user_id" not in session(client)
