"""The JSON "session instructions" returned by the register and refresh endpoints (spec §JSON format)."""

from django_dbsc import conf
from django_dbsc.constants import BOUND_COOKIE_NAME
from django_dbsc.services.cookie import declared_attributes


def session_instructions(session_identifier: str) -> dict:
    return {
        "session_identifier": session_identifier,
        "refresh_url": conf.get("REFRESH_URL"),
        "scope": {
            # Origin-scoped. Site scope also needs /.well-known/device-bound-sessions, which isn't supported yet.
            "include_site": False,
            # WHY mirror the middleware's exemptions: otherwise the browser would block those requests on a refresh
            # the server never asked for.
            "scope_specification": [{"type": "exclude", "path": prefix} for prefix in conf.get("EXEMPT_PATH_PREFIXES")],
        },
        "credentials": [{"type": "cookie", "name": BOUND_COOKIE_NAME, "attributes": declared_attributes()}],
    }
