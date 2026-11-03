import pytest
from django.core.cache import cache

from django_dbsc.services.challenge import ChallengeStore


class FakeClock:
    def __init__(self, now: float = 1_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(clock):
    cache.clear()
    return ChallengeStore(cache=cache, ttl=120, keep=3, clock=clock)


def test_issued_challenge_is_active_for_its_scope(store):
    challenge = store.issue("s1")

    assert challenge in store.active("s1")


def test_challenges_are_unique_and_unguessable(store):
    issued = {store.issue("s1") for _ in range(3)}

    assert len(issued) == 3
    assert all(len(c) >= 32 for c in issued)


def test_scopes_are_isolated(store):
    challenge = store.issue("s1")

    assert challenge not in store.active("s2")


def test_consume_is_one_time(store):
    challenge = store.issue("s1")

    assert store.consume("s1", challenge) is True
    assert store.consume("s1", challenge) is False
    assert challenge not in store.active("s1")


def test_consume_unknown_challenge_fails(store):
    assert store.consume("s1", "never-issued") is False


def test_consume_non_ascii_attacker_input_fails_cleanly(store):
    store.issue("s1")

    assert store.consume("s1", "ü-not-ascii") is False


def test_challenges_expire_after_ttl(store, clock):
    challenge = store.issue("s1")

    clock.now += 121

    assert challenge not in store.active("s1")
    assert store.consume("s1", challenge) is False


def test_recent_challenges_stay_valid_to_absorb_latency_races(store):
    # The spec warns that a proof for an older challenge can arrive after a newer one was issued.
    first = store.issue("s1")
    second = store.issue("s1")

    assert {first, second} <= store.active("s1")


def test_only_the_most_recent_challenges_are_kept(store):
    oldest = store.issue("s1")
    for _ in range(3):
        store.issue("s1")

    assert oldest not in store.active("s1")
    assert len(store.active("s1")) == 3
