import pytest
from django.contrib.auth import get_user_model

from django_dbsc.models import DeviceBoundSession
from django_dbsc.repositories import DeviceBoundSessionRepository
from tests.support import DeviceKey

pytestmark = pytest.mark.django_db


@pytest.fixture
def user():
    return get_user_model().objects.create_user("alice", password="x")


@pytest.fixture
def repo():
    return DeviceBoundSessionRepository()


@pytest.fixture
def device():
    return DeviceKey("ES256")


def test_create_assigns_unguessable_unique_identifier(repo, user, device):
    first = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")
    second = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")

    assert first.session_identifier != second.session_identifier
    assert len(first.session_identifier) >= 32


def test_get_active_returns_stored_key_material(repo, user, device):
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")

    found = repo.get_active(created.session_identifier)

    assert found is not None
    assert found.public_jwk == device.public_jwk
    assert found.alg == "ES256"
    assert found.user == user


def test_get_active_unknown_identifier_returns_none(repo):
    assert repo.get_active("does-not-exist") is None


def test_revoked_session_is_not_active(repo, user, device):
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")

    assert repo.revoke(created.session_identifier) is True
    assert repo.get_active(created.session_identifier) is None


def test_revoking_twice_reports_nothing_revoked(repo, user, device):
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")
    repo.revoke(created.session_identifier)

    assert repo.revoke(created.session_identifier) is False


def test_revoke_all_for_user_leaves_other_users_alone(repo, user, device):
    bob = get_user_model().objects.create_user("bob", password="x")
    a1 = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")
    a2 = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")
    b1 = repo.create(user=bob, public_jwk=device.public_jwk, alg="ES256")

    assert repo.revoke_all_for_user(user) == 2
    assert repo.get_active(a1.session_identifier) is None
    assert repo.get_active(a2.session_identifier) is None
    assert repo.get_active(b1.session_identifier) is not None


def test_mark_refreshed_records_timestamp(repo, user, device):
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")
    assert created.last_refreshed_at is None

    repo.mark_refreshed(created)

    assert repo.get_active(created.session_identifier).last_refreshed_at is not None


def test_rejects_unsupported_alg(repo, user, device):
    with pytest.raises(ValueError, match="alg"):
        repo.create(user=user, public_jwk=device.public_jwk, alg="none")


def test_rejects_private_key_material(repo, user):
    # A jwk carrying "d" means the key was exported, so it is no longer device-bound. Never store it.
    leaked = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "secret"}

    with pytest.raises(ValueError, match="private"):
        repo.create(user=user, public_jwk=leaked, alg="ES256")


def test_revoke_records_reason(repo, user, device):
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")

    repo.revoke(created.session_identifier, reason="logout")

    assert DeviceBoundSession.objects.get(pk=created.pk).revoked_reason == "logout"


def test_revoke_all_records_reason(repo, user, device):
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")

    repo.revoke_all_for_user(user, reason="password_changed")

    assert DeviceBoundSession.objects.get(pk=created.pk).revoked_reason == "password_changed"


def test_second_revoke_keeps_the_first_reason(repo, user, device):
    # The first reason is the true cause. A later cleanup must not overwrite the audit trail.
    created = repo.create(user=user, public_jwk=device.public_jwk, alg="ES256")
    repo.revoke(created.session_identifier, reason="missing_bound_cookie")

    repo.revoke(created.session_identifier, reason="logout")

    assert DeviceBoundSession.objects.get(pk=created.pk).revoked_reason == "missing_bound_cookie"
