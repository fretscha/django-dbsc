import pytest
from django.contrib.auth import get_user_model

from django_dbsc.services.challenge import ChallengeStore, registration_scope
from tests.support import parse_registration

pytestmark = pytest.mark.django_db

HEADER = "Secure-Session-Registration"


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


def _login(client, password="pw"):
    return client.post("/login/", {"username": "alice", "password": password})


def _challenge_from(response) -> str:
    ((_, params),) = parse_registration(response.headers[HEADER])
    return params["challenge"]


def test_successful_login_offers_registration(client, alice):
    response = _login(client)

    assert response.status_code == 200
    assert HEADER in response.headers


def test_offered_challenge_is_active_for_this_session_only(client, alice):
    response = _login(client)

    challenge = _challenge_from(response)
    store = ChallengeStore()
    assert challenge in store.active(registration_scope(client.session.session_key))
    assert challenge not in store.active(registration_scope("another-session"))


def test_failed_login_offers_nothing(client, alice):
    response = _login(client, password="wrong")

    assert HEADER not in response.headers


def test_ordinary_requests_offer_nothing(client, alice):
    _login(client)

    assert HEADER not in client.get("/protected/").headers


def test_registration_path_comes_from_settings(client, alice, settings):
    settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "REGISTRATION_PATH": "/custom/register"}

    response = _login(client)

    ((_, params),) = parse_registration(response.headers[HEADER])
    assert params["path"] == "/custom/register"
