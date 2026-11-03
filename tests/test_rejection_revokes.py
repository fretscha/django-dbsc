"""When the middleware rejects a bound session, the binding is revoked too, so it can't linger as a live record."""

import logging

import pytest
from django.contrib.auth import get_user_model
from django.db import DatabaseError

from django_dbsc.constants import BOUND_COOKIE_NAME
from django_dbsc.models import DeviceBoundSession
from django_dbsc.repositories import DeviceBoundSessionRepository
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


@pytest.fixture
def stolen(client, alice):
    """A bound session replayed without its bound cookie: the stolen-sessionid case."""
    sid, _ = register_browser(client, DeviceKey())
    del client.cookies[BOUND_COOKIE_NAME]
    return sid


def test_rejection_revokes_binding_with_reason(client, stolen):
    assert client.get("/protected/").status_code == 401

    record = DeviceBoundSession.objects.get(session_identifier=stolen)
    assert record.revoked_at is not None
    assert record.revoked_reason == "missing_bound_cookie"


def test_logout_records_its_reason(client, alice):
    sid, _ = register_browser(client, DeviceKey())

    client.post("/logout/")

    assert DeviceBoundSession.objects.get(session_identifier=sid).revoked_reason == "logout"


def test_revocation_failure_still_rejects(client, stolen, monkeypatch, caplog):
    def broken(self, session_identifier, reason=""):
        raise DatabaseError("connection lost")

    monkeypatch.setattr(DeviceBoundSessionRepository, "revoke", broken)

    with caplog.at_level(logging.ERROR, logger="django_dbsc"):
        response = client.get("/protected/")

    assert response.status_code == 401
    assert stolen in caplog.text
