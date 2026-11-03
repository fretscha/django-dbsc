"""Secure-Session-Skipped may soften a rejection, but must never grant access.

Real-browser finding: Chrome skips refreshes when over its signing quota and sends this header. Treating that like
theft logged legitimate users out. A thief gains nothing from forging it: the request is still refused.
"""

import pytest
from django.contrib.auth import get_user_model

from django_dbsc.constants import BOUND_COOKIE_NAME, SESSION_DBSC_ID
from django_dbsc.models import DeviceBoundSession
from django_dbsc.services.skipped import names_session
from tests.support import DeviceKey, register_browser

pytestmark = pytest.mark.django_db


@pytest.fixture
def alice():
    return get_user_model().objects.create_user("alice", password="pw")


@pytest.fixture
def expired(client, alice):
    """A bound browser whose bound cookie has expired. Returns (device, sid, refresh_challenge)."""
    device = DeviceKey()
    sid, challenge = register_browser(client, device)
    del client.cookies[BOUND_COOKIE_NAME]
    return device, sid, challenge


def _skipped(sid: str, reason: str = "quota_exceeded") -> dict:
    return {"Secure-Session-Skipped": f'{reason};session_identifier="{sid}"'}


class TestSoftenedRejection:
    def test_skipped_refresh_is_still_refused(self, client, expired):
        _, sid, _ = expired

        assert client.get("/protected/", headers=_skipped(sid)).status_code == 401

    def test_skipped_refresh_keeps_session_and_binding(self, client, expired):
        _, sid, _ = expired

        client.get("/protected/", headers=_skipped(sid))

        assert client.session[SESSION_DBSC_ID] == sid
        assert "_auth_user_id" in client.session
        assert DeviceBoundSession.objects.get(session_identifier=sid).revoked_at is None

    def test_next_successful_refresh_recovers(self, client, expired):
        device, sid, challenge = expired
        client.get("/protected/", headers=_skipped(sid))

        client.post(
            "/dbsc/refresh",
            headers={"Sec-Secure-Session-Id": sid, "Secure-Session-Response": device.refresh_proof(challenge)},
        )

        # /protected/ has no login check in the test project, so assert the binding itself was restored.
        assert client.get("/bound-status/").content == b"True"

    @pytest.mark.parametrize("reason", ["unreachable", "server_error", "quota_exceeded"])
    def test_all_spec_reasons_soften(self, client, expired, reason):
        _, sid, _ = expired

        client.get("/protected/", headers=_skipped(sid, reason))

        assert client.session[SESSION_DBSC_ID] == sid


class TestStrictRejection:
    def test_skipped_header_for_another_session_is_strict(self, client, expired):
        _, sid, _ = expired

        client.get("/protected/", headers=_skipped("someone-elses-sid"))

        assert SESSION_DBSC_ID not in client.session
        assert DeviceBoundSession.objects.get(session_identifier=sid).revoked_reason == "missing_bound_cookie"

    def test_malformed_skipped_header_is_strict(self, client, expired):
        _, sid, _ = expired

        client.get("/protected/", headers={"Secure-Session-Skipped": '"unterminated'})

        assert SESSION_DBSC_ID not in client.session
        assert DeviceBoundSession.objects.get(session_identifier=sid).revoked_reason == "missing_bound_cookie"

    def test_no_skipped_header_is_strict(self, client, expired):
        client.get("/protected/")

        assert SESSION_DBSC_ID not in client.session


class TestNamesSession:
    def test_matches_quoted_identifier(self):
        assert names_session('quota_exceeded;session_identifier="abc"', "abc")

    def test_matches_any_entry_of_the_list(self):
        assert names_session('unreachable;session_identifier="x", quota_exceeded;session_identifier="abc"', "abc")

    def test_rejects_other_identifier(self):
        assert not names_session('quota_exceeded;session_identifier="abc"', "abd")

    def test_rejects_entry_without_identifier(self):
        assert not names_session("quota_exceeded", "abc")

    @pytest.mark.parametrize("value", [None, "", '"unterminated', "ü", "quota_exceeded;session_identifier=?1"])
    def test_rejects_absent_or_malformed(self, value):
        assert not names_session(value, "abc")
