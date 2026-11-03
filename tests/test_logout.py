import logging

import pytest
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client

from django_dbsc.constants import BOUND_COOKIE_NAME
from django_dbsc.models import DeviceBoundSession
from django_dbsc.repositories import DeviceBoundSessionRepository
from django_dbsc.services import logout as logout_service
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


def _is_revoked(sid: str) -> bool:
    return DeviceBoundSession.objects.get(session_identifier=sid).revoked_at is not None


def test_logout_revokes_this_sessions_device_binding(client, alice):
    sid, _ = register_browser(client, DeviceKey())

    client.post("/logout/")

    assert _is_revoked(sid)


def test_logout_clears_the_bound_cookie(client, alice):
    register_browser(client, DeviceKey())

    response = client.post("/logout/")

    assert response.cookies[BOUND_COOKIE_NAME]["max-age"] == 0


def test_logout_leaves_the_users_other_devices_alone(alice):
    laptop, phone = Client(), Client()
    laptop_sid, _ = register_browser(laptop, DeviceKey())
    phone_sid, _ = register_browser(phone, DeviceKey())

    laptop.post("/logout/")

    assert _is_revoked(laptop_sid)
    assert not _is_revoked(phone_sid)


def test_logout_of_unbound_session_is_a_no_op(client, alice):
    client.force_login(alice)

    response = client.post("/logout/")

    assert response.status_code == 200
    assert BOUND_COOKIE_NAME not in response.cookies


def test_refresh_after_logout_terminates(client, alice):
    device = DeviceKey()
    sid, challenge = register_browser(client, device)
    client.post("/logout/")

    response = client.post(
        "/dbsc/refresh",
        headers={"Sec-Secure-Session-Id": sid, "Secure-Session-Response": device.refresh_proof(challenge)},
    )

    assert response.status_code == 401


def test_revocation_failure_never_blocks_logout(client, alice, monkeypatch, caplog):
    # WHY: a user who clicks "log out" must end up logged out even if the DB is down. The flush still happens.
    sid, _ = register_browser(client, DeviceKey())

    class BrokenRepo(DeviceBoundSessionRepository):
        def revoke(self, session_identifier, reason=""):
            raise DatabaseError("connection lost")

    monkeypatch.setattr(logout_service, "get_repository", BrokenRepo)

    with caplog.at_level(logging.ERROR, logger="django_dbsc"):
        response = client.post("/logout/")

    assert response.status_code == 200
    assert "_auth_user_id" not in client.session
    assert sid in caplog.text
