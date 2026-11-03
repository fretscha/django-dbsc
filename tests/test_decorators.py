import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory

from django_dbsc.decorators import device_bound_required
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


def test_bound_session_reaches_the_view(client, alice):
    register_browser(client, DeviceKey())

    response = client.get("/sensitive/")

    assert response.status_code == 200
    assert response.content == b"sensitive"


def test_unbound_logged_in_session_is_refused(client, alice):
    client.force_login(alice)

    assert client.get("/sensitive/").status_code == 403


def test_anonymous_is_refused(client):
    assert client.get("/sensitive/").status_code == 403


def test_unbound_is_sent_to_step_up_when_configured(client, alice, settings):
    settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, "STEP_UP_URL": "/reauth/"}
    client.force_login(alice)

    response = client.get("/sensitive/?tab=2")

    assert response.status_code == 302
    assert response.headers["Location"] == "/reauth/?next=/sensitive/%3Ftab%3D2"


def test_refuses_when_middleware_is_missing():
    # Fail closed: without the middleware nobody verified the bound cookie, so the decorator must not guess.
    request = RequestFactory().get("/sensitive/")
    request.user = AnonymousUser()

    @device_bound_required
    def view(request):
        return HttpResponse("sensitive")

    with pytest.raises(ImproperlyConfigured, match="DeviceBoundSessionMiddleware"):
        view(request)


def test_preserves_view_metadata():
    @device_bound_required
    def my_view(request):
        """Docstring."""

    assert my_view.__name__ == "my_view"
    assert my_view.__doc__ == "Docstring."
