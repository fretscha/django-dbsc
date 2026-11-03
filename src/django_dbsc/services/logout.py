"""Logout ends the device binding too, so a key that is still registered in the browser can't revive the session."""

import logging

from django.db import DatabaseError

from django_dbsc.constants import BOUND_COOKIE_NAME, SESSION_DBSC_ID
from django_dbsc.repositories import DeviceBoundSessionRepository
from django_dbsc.services.cookie import COOKIE_ATTRIBUTES

logger = logging.getLogger("django_dbsc")

# Factory rather than an instance, so tests (and integrators) can swap the repository.
get_repository = DeviceBoundSessionRepository

_CLEAR_FLAG = "_dbsc_clear_bound_cookie"


def revoke_on_logout(sender, request, user, **kwargs) -> None:
    """``user_logged_out`` receiver. Django sends it before flushing the session, so the binding is still readable."""
    if request is None:
        return
    sid = request.session.get(SESSION_DBSC_ID)
    if not sid:
        return
    setattr(request, _CLEAR_FLAG, True)
    try:
        get_repository().revoke(sid, reason="logout")
    except DatabaseError:
        # WHY swallow: logout must always succeed. The session flush still kills this session, and the stale
        # binding can't be reached without it.
        logger.exception("[DBSC] could not revoke binding on logout dbsc_id=%s", sid)
    else:
        logger.info("[DBSC] binding revoked on logout dbsc_id=%s", sid)


def clear_bound_cookie(request, response) -> None:
    if getattr(request, _CLEAR_FLAG, False):
        response.delete_cookie(
            BOUND_COOKIE_NAME, path=COOKIE_ATTRIBUTES["path"], samesite=COOKIE_ATTRIBUTES["samesite"]
        )
