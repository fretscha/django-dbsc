"""End-to-end behaviour of REQUIRE_BINDING (mode C) through the real middleware stack."""

import time

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

from django_dbsc.constants import SESSION_BINDING_REQUIRED_SINCE
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db

GRACE = 30


@pytest.fixture(autouse=True)
def staff_must_bind(settings):
    settings.DJANGO_DBSC = {
        **settings.DJANGO_DBSC,
        "REQUIRE_BINDING": "django_dbsc.policies.staff_only",
        "BINDING_GRACE_SECONDS": GRACE,
    }


@pytest.fixture
def admin_user():
    return get_user_model().objects.create_user("alice", password="pw", is_staff=True)


@pytest.fixture
def regular_user():
    return get_user_model().objects.create_user("bob", password="pw")


def _expire_grace(client):
    session = client.session
    session[SESSION_BINDING_REQUIRED_SINCE] = int(time.time()) - GRACE - 1
    session.save()


def test_staff_may_browse_during_grace(client, admin_user):
    # Registration runs in the background after login, so the first page loads usually arrive unbound.
    client.force_login(admin_user)

    assert client.get("/protected/").status_code == 200


def test_staff_still_unbound_after_grace_is_logged_out(client, admin_user):
    client.force_login(admin_user)
    client.get("/protected/")
    _expire_grace(client)

    response = client.get("/protected/")

    assert response.status_code == 403
    assert "_auth_user_id" not in client.session


def test_regular_users_are_not_affected(client, regular_user):
    client.force_login(regular_user)
    _expire_grace(client)

    assert client.get("/protected/").status_code == 200


def test_bound_staff_session_passes_after_grace(client, admin_user):
    register_browser(client, DeviceKey())
    _expire_grace(client)

    assert client.get("/protected/").status_code == 200


def test_registration_endpoint_stays_reachable_after_grace(client, admin_user):
    # A slow browser must still be able to finish binding, so exempt paths ignore the policy.
    client.force_login(admin_user)
    _expire_grace(client)

    response = client.post("/dbsc/register")

    assert response.status_code == 400  # rejected by the endpoint for lacking a proof, not by the policy


def test_existing_sessions_are_covered_on_rollout(client, admin_user, settings):
    # Sessions created before the policy was enabled get their grace period from the first request seen.
    settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "REQUIRE_BINDING": None}
    client.force_login(admin_user)
    assert SESSION_BINDING_REQUIRED_SINCE not in client.session

    settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "REQUIRE_BINDING": "django_dbsc.policies.staff_only"}
    # A new Client builds a new handler, so the middleware loads the new policy, as it would after a deploy.
    fresh_handler = Client()
    fresh_handler.cookies = client.cookies

    assert fresh_handler.get("/protected/").status_code == 200
    assert SESSION_BINDING_REQUIRED_SINCE in fresh_handler.session


class TestViolationResponse:
    """What a user sees when their account requires binding and their browser couldn't bind."""

    def _violate(self, client, admin_user):
        client.force_login(admin_user)
        client.get("/protected/")
        _expire_grace(client)
        return client.get("/protected/")

    def test_redirects_to_configured_page(self, client, admin_user, settings):
        settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "BINDING_REQUIRED_URL": "/browser-required/"}

        response = self._violate(client, admin_user)

        assert response.status_code == 302
        assert response.headers["Location"] == "/browser-required/"
        assert "_auth_user_id" not in client.session

    def test_redirect_target_does_not_loop(self, client, admin_user, settings):
        # The session is ended before redirecting, so the target page is no longer subject to the policy.
        settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "BINDING_REQUIRED_URL": "/browser-required/"}

        response = self._violate(client, admin_user)
        target = client.get(response.headers["Location"])

        assert target.status_code == 200

    def test_without_url_renders_explanatory_template(self, client, admin_user):
        response = self._violate(client, admin_user)

        assert response.status_code == 403
        assert "django_dbsc/binding_required.html" in [t.name for t in response.templates]
        assert b"device-bound" in response.content.lower()

    def test_template_can_be_overridden(self, client, admin_user, settings, tmp_path):
        (tmp_path / "django_dbsc").mkdir()
        (tmp_path / "django_dbsc" / "binding_required.html").write_text("Use Chrome on your work laptop.")
        settings.TEMPLATES = [{**settings.TEMPLATES[0], "DIRS": [tmp_path]}]

        response = self._violate(client, admin_user)

        assert response.content == b"Use Chrome on your work laptop."

    def test_falls_back_to_plain_text_without_template_engine(self, client, admin_user, settings):
        # Projects without TEMPLATES (pure APIs) must still get a clean 403, never a 500.
        settings.TEMPLATES = []

        response = self._violate(client, admin_user)

        assert response.status_code == 403
        assert b"device-bound" in response.content.lower()
