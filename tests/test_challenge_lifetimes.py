"""Challenge lifetimes must fit how browsers actually use them.

Real-browser finding: Chrome caches the challenge from our last 200 and signs it at the next refresh, which with a
600 s bound cookie comes ~8 min later (it refreshes when <2 min remain). A 120 s TTL meant every real refresh
first hit 403 and needed a retry round trip.
"""

import time

import http_sf
import pytest
from django.contrib.auth import get_user_model

from tests.support import DeviceKey, parse_registration, register_browser

pytestmark = pytest.mark.django_db

MAX_AGE = 600  # the default BOUND_COOKIE_MAX_AGE


@pytest.fixture
def clock(monkeypatch):
    """Moves time.time() forward for everything: challenge stores, the signed cookie, and the locmem cache."""
    real = time.time
    state = {"offset": 0.0}
    monkeypatch.setattr(time, "time", lambda: real() + state["offset"])

    def advance(seconds: float) -> None:
        state["offset"] += seconds

    return advance


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


def _refresh(client, device, sid, challenge):
    return client.post(
        "/dbsc/refresh",
        headers={"Sec-Secure-Session-Id": sid, "Secure-Session-Response": device.refresh_proof(challenge)},
    )


class TestRefreshChallenges:
    def test_challenge_from_registration_is_still_valid_at_chromes_refresh_point(self, client, alice, clock):
        device = DeviceKey()
        sid, challenge = register_browser(client, device)

        clock(MAX_AGE - 120)  # Chrome refreshes proactively once <2 min of the bound cookie remain

        assert _refresh(client, device, sid, challenge).status_code == 200

    def test_challenge_from_refresh_is_still_valid_at_the_next_refresh(self, client, alice, clock):
        device = DeviceKey()
        sid, first = register_browser(client, device)
        response = _refresh(client, device, sid, first)
        second, _ = http_sf.parse(response.headers["Secure-Session-Challenge"].encode(), tltype="item")

        clock(MAX_AGE - 120)

        assert _refresh(client, device, sid, second).status_code == 200

    def test_challenge_expires_shortly_after_the_cookie_lifetime(self, client, alice, clock):
        device = DeviceKey()
        sid, challenge = register_browser(client, device)

        clock(MAX_AGE + 61)

        assert _refresh(client, device, sid, challenge).status_code == 403

    def test_ttl_can_be_overridden(self, client, alice, clock, settings):
        settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "REFRESH_CHALLENGE_TTL": 30}
        device = DeviceKey()
        sid, challenge = register_browser(client, device)

        clock(31)

        assert _refresh(client, device, sid, challenge).status_code == 403


class TestRegistrationChallenges:
    def test_registration_challenge_stays_short_lived(self, client, alice, clock):
        # Registration follows the login response within milliseconds, so there's no reason to widen this window.
        login = client.post("/login/", {"username": "alice", "password": "pw"})
        ((_, params),) = parse_registration(login.headers["Secure-Session-Registration"])

        clock(121)

        response = client.post(
            "/dbsc/register", headers={"Secure-Session-Response": DeviceKey().registration_proof(params["challenge"])}
        )
        assert response.status_code == 400
