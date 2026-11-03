"""Pins docs/guide.md: revoke_all_for_user takes effect within BOUND_COOKIE_MAX_AGE, then the session ends."""

import time

import pytest
from django.contrib.auth import get_user_model

from django_dbsc.constants import BOUND_COOKIE_NAME
from django_dbsc.repositories import DeviceBoundSessionRepository
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db


@pytest.fixture
def clock(monkeypatch):
    real = time.time
    state = {"offset": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + state["offset"])
    return lambda seconds: state.__setitem__("offset", state["offset"] + seconds)


def test_revoked_device_works_until_cookie_expiry_then_session_ends(client, clock):
    alice = get_user_model().objects.create_user("alice", password="pw")
    device = DeviceKey()
    sid, challenge = register_browser(client, device)

    DeviceBoundSessionRepository().revoke_all_for_user(alice, reason="password_changed")

    # The bound cookie is verified without a DB lookup, so the device keeps working until it expires.
    assert client.get("/bound-status/").content == b"True"

    clock(601)
    refresh = client.post(
        "/dbsc/refresh",
        headers={"Sec-Secure-Session-Id": sid, "Secure-Session-Response": device.refresh_proof(challenge)},
    )
    assert refresh.status_code == 401  # the browser drops its DBSC session

    del client.cookies[BOUND_COOKIE_NAME]  # expired in the browser
    assert client.get("/protected/").status_code == 401
    assert "_auth_user_id" not in client.session
