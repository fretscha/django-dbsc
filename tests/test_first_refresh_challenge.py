"""Chrome appears to ignore the challenge on the register response (its session doesn't exist yet), so the first
refresh always needed a 403 retry. The first bound response after registration therefore carries a fresh one.
"""

import time

import http_sf
import pytest
from django.contrib.auth import get_user_model

from django_dbsc.services.challenge import ChallengeStore, refresh_scope
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db

HEADER = "Secure-Session-Challenge"


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


@pytest.fixture
def device():
    return DeviceKey()


def _challenge(response) -> tuple[str, dict]:
    return http_sf.parse(response.headers[HEADER].encode(), tltype="item")


def test_first_bound_response_carries_a_refresh_challenge(client, alice, device):
    sid, _ = register_browser(client, device)

    response = client.get("/protected/")

    challenge, params = _challenge(response)
    assert params["id"] == sid
    assert challenge in ChallengeStore().active(refresh_scope(sid))


def test_only_the_first_bound_response_carries_it(client, alice, device):
    register_browser(client, device)
    client.get("/protected/")

    assert HEADER not in client.get("/protected/").headers


def test_exempt_paths_dont_use_it_up(client, alice, device):
    # The browser excludes these from the session scope, so a challenge there might not be cached.
    register_browser(client, device)

    assert HEADER not in client.get("/static/app.css").headers
    assert HEADER in client.get("/protected/").headers


def test_unbound_sessions_get_none(client, alice):
    client.force_login(alice)

    assert HEADER not in client.get("/protected/").headers


def test_that_challenge_is_valid_at_chromes_first_refresh(client, alice, device, monkeypatch):
    sid, _ = register_browser(client, device)
    challenge, _ = _challenge(client.get("/protected/"))
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 600 - 120)  # Chrome refreshes when <2 min remain

    response = client.post(
        "/dbsc/refresh",
        headers={"Sec-Secure-Session-Id": sid, "Secure-Session-Response": device.refresh_proof(challenge)},
    )

    assert response.status_code == 200
