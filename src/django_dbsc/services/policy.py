"""Mode C: require certain users' sessions to become device-bound within a grace period after they first appear.

The grace period exists because the browser registers in the background after the login response, so the first
page loads usually arrive before the binding exists. It is measured in seconds, not requests, because a request
count says nothing about whether the background registration has had time to finish.
"""

import enum
import time
from collections.abc import Callable

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from django_dbsc.constants import SESSION_BINDING_REQUIRED_SINCE


class Verdict(enum.Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    VIOLATION = "violation"


class BindingPolicy:
    def __init__(self, requires: Callable[[object], bool] | None, grace_seconds: int, clock=None):
        self.requires = requires
        self.grace_seconds = grace_seconds
        self.clock = clock or time.time

    def evaluate(self, session, user) -> Verdict:
        """Judge an *unbound* session. Bound sessions are handled by the bound-cookie check instead."""
        if self.requires is None or not user.is_authenticated or not self.requires(user):
            return Verdict.NOT_REQUIRED
        now = int(self.clock())
        # WHY stamp on first sighting rather than at login: sessions that predate the policy, or users promoted to
        # staff mid-session, still get a fair grace period instead of being logged out on rollout.
        since = session.setdefault(SESSION_BINDING_REQUIRED_SINCE, now)
        return Verdict.PENDING if now - since <= self.grace_seconds else Verdict.VIOLATION


def load_policy(setting, grace_seconds: int) -> BindingPolicy:
    if setting is None or callable(setting):
        return BindingPolicy(requires=setting, grace_seconds=grace_seconds)
    try:
        requires = import_string(setting)
    except ImportError as exc:
        raise ImproperlyConfigured(f"DJANGO_DBSC['REQUIRE_BINDING'] = {setting!r} cannot be imported: {exc}") from exc
    return BindingPolicy(requires=requires, grace_seconds=grace_seconds)
