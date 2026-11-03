"""Pins docs/security.md: flooding /dbsc/refresh can't grow the cache."""

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache

from django_dbsc.services.challenge import KEY_PREFIX, refresh_scope
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db


def test_requests_without_a_bound_session_write_nothing(client):
    cache.clear()

    for i in range(50):
        response = client.post("/dbsc/refresh", headers={"Sec-Secure-Session-Id": f"forged-{i}"})
        assert response.status_code == 401

    assert all(cache.get(KEY_PREFIX + refresh_scope(f"forged-{i}")) is None for i in range(50))


def test_a_bound_session_holds_at_most_three_challenges(client):
    get_user_model().objects.create_user("alice", password="pw")
    sid, _ = register_browser(client, DeviceKey())

    for _ in range(50):
        assert client.post("/dbsc/refresh", headers={"Sec-Secure-Session-Id": sid}).status_code == 403

    assert len(cache.get(KEY_PREFIX + refresh_scope(sid))) == 3
