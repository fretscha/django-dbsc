from django.conf import settings

DEFAULTS = {
    "EXEMPT_PATH_PREFIXES": ["/dbsc/"],
    "BOUND_COOKIE_MAX_AGE": 600,
    "REGISTRATION_PATH": "/dbsc/register",
    "REFRESH_URL": "/dbsc/refresh",
    # Where @device_bound_required sends unbound sessions (e.g. a re-auth/MFA view). None means answer 403.
    "STEP_UP_URL": None,
    # Mode C. A callable(user) -> bool, or its dotted path, picking users whose sessions MUST become bound.
    # None means opportunistic only.
    "REQUIRE_BINDING": None,
    "BINDING_GRACE_SECONDS": 30,
}


def get(name: str):
    return getattr(settings, "DJANGO_DBSC", {}).get(name, DEFAULTS[name])
