import pytest

from django_dbsc.middleware import BOUND_COOKIE_NAME, SESSION_DBSC_ID
from django_dbsc.services.cookie import BoundCookieCodec

# Rejecting a bound session revokes its binding, so these tests touch the DB.
pytestmark = pytest.mark.django_db


@pytest.fixture
def bound_client(client):
    session = client.session
    session[SESSION_DBSC_ID] = "s1"
    session.save()
    return client


def test_unbound_session_passes_through(client):
    # Browsers without DBSC never register, so they must keep working.
    assert client.get("/protected/").status_code == 200


def test_bound_session_with_valid_cookie_passes(bound_client):
    bound_client.cookies[BOUND_COOKIE_NAME] = BoundCookieCodec().encode("s1")

    assert bound_client.get("/protected/").status_code == 200


def test_bound_session_without_cookie_is_rejected_and_logged_out(bound_client):
    # This is the stolen-sessionid case: the attacker has the session cookie but not the device key.
    response = bound_client.get("/protected/")

    assert response.status_code == 401
    assert SESSION_DBSC_ID not in bound_client.session


def test_bound_cookie_from_another_session_is_rejected(bound_client):
    bound_client.cookies[BOUND_COOKIE_NAME] = BoundCookieCodec().encode("someone-else")

    assert bound_client.get("/protected/").status_code == 401


def test_forged_skipped_header_does_not_bypass_enforcement(bound_client):
    response = bound_client.get("/protected/", headers={"Secure-Session-Skipped": "unreachable;session_identifier=s1"})

    assert response.status_code == 401


def test_exempt_paths_are_not_enforced(bound_client):
    # Exempt paths are excluded from the DBSC scope, so the browser never attaches a bound cookie to them.
    # 404 (there is no such static file) proves the request got past the middleware rather than being refused with 401.
    assert bound_client.get("/static/app.css").status_code == 404
    assert SESSION_DBSC_ID in bound_client.session


class TestBoundFlag:
    """request.dbsc_bound tells views whether *this request* proved device possession."""

    def test_unbound_session_is_not_bound(self, client):
        assert client.get("/bound-status/").content == b"False"

    def test_bound_session_with_valid_cookie_is_bound(self, bound_client):
        bound_client.cookies[BOUND_COOKIE_NAME] = BoundCookieCodec().encode("s1")

        assert bound_client.get("/bound-status/").content == b"True"

    def test_valid_looking_cookie_without_session_binding_is_not_bound(self, client):
        # The cookie alone means nothing: it must match the binding recorded in the server-side session.
        client.cookies[BOUND_COOKIE_NAME] = BoundCookieCodec().encode("s1")

        assert client.get("/bound-status/").content == b"False"
