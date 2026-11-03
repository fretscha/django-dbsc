from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured

from django_dbsc import policies
from django_dbsc.constants import SESSION_BINDING_REQUIRED_SINCE
from django_dbsc.services.policy import BindingPolicy, Verdict, load_policy


class FakeClock:
    def __init__(self, now: float = 1_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


def staff(**kw):
    return SimpleNamespace(is_authenticated=True, is_staff=True, is_superuser=False, **kw)


def regular():
    return SimpleNamespace(is_authenticated=True, is_staff=False, is_superuser=False)


def anonymous():
    return SimpleNamespace(is_authenticated=False, is_staff=False, is_superuser=False)


def policy_for_staff(clock, grace=30):
    return BindingPolicy(requires=policies.staff_only, grace_seconds=grace, clock=clock)


class TestVerdicts:
    def test_without_policy_nothing_is_required(self, clock):
        assert BindingPolicy(requires=None, grace_seconds=30, clock=clock).evaluate({}, staff()) is Verdict.NOT_REQUIRED

    def test_anonymous_is_never_required(self, clock):
        assert policy_for_staff(clock).evaluate({}, anonymous()) is Verdict.NOT_REQUIRED

    def test_users_outside_the_policy_are_not_required_and_not_stamped(self, clock):
        session = {}

        assert policy_for_staff(clock).evaluate(session, regular()) is Verdict.NOT_REQUIRED
        assert session == {}

    def test_first_sighting_starts_the_grace_period(self, clock):
        session = {}

        assert policy_for_staff(clock).evaluate(session, staff()) is Verdict.PENDING
        assert session[SESSION_BINDING_REQUIRED_SINCE] == 1_000

    def test_still_pending_at_end_of_grace(self, clock):
        session = {}
        policy = policy_for_staff(clock, grace=30)
        policy.evaluate(session, staff())

        clock.now += 30

        assert policy.evaluate(session, staff()) is Verdict.PENDING

    def test_violation_after_grace(self, clock):
        session = {}
        policy = policy_for_staff(clock, grace=30)
        policy.evaluate(session, staff())

        clock.now += 31

        assert policy.evaluate(session, staff()) is Verdict.VIOLATION

    def test_later_requests_do_not_restart_the_grace_period(self, clock):
        session = {}
        policy = policy_for_staff(clock, grace=30)
        for _ in range(4):
            policy.evaluate(session, staff())
            clock.now += 10

        assert policy.evaluate(session, staff()) is Verdict.VIOLATION


class TestLoading:
    def test_dotted_path(self):
        assert load_policy("django_dbsc.policies.staff_only", 30).requires is policies.staff_only

    def test_callable(self):
        def rule(user):
            return True

        assert load_policy(rule, 30).requires is rule

    def test_none_disables(self):
        assert load_policy(None, 30).requires is None

    def test_bad_path_is_a_configuration_error(self):
        with pytest.raises(ImproperlyConfigured, match="REQUIRE_BINDING"):
            load_policy("django_dbsc.policies.no_such_policy", 30)


class TestBuiltInPolicies:
    def test_staff_only(self):
        assert policies.staff_only(staff())
        assert not policies.staff_only(regular())

    def test_superusers_only(self):
        assert policies.superusers_only(SimpleNamespace(is_superuser=True))
        assert not policies.superusers_only(staff())

    def test_everyone(self):
        assert policies.everyone(regular())
