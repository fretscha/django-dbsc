import logging

from django.db import DatabaseError
from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django_dbsc import conf
from django_dbsc.constants import CHALLENGE_HEADER, RESPONSE_HEADER, SESSION_ID_HEADER
from django_dbsc.services.cookie import BoundCookieCodec, set_bound_cookie
from django_dbsc.services.headers import challenge_header
from django_dbsc.services.instructions import session_instructions
from django_dbsc.services.refresh import ChallengeRequired, RefreshError, RefreshService
from django_dbsc.services.registration import RegistrationError, RegistrationService

logger = logging.getLogger("django_dbsc")


def get_registration_service() -> RegistrationService:
    return RegistrationService()


def get_refresh_service() -> RefreshService:
    return RefreshService()


def dbsc_endpoint(view):
    """Hardening shared by every DBSC endpoint."""
    # csrf_exempt: the browser makes these POSTs without a CSRF token. The signed proof is the anti-forgery check.
    # never_cache and xframe DENY follow the spec's security considerations. No CORS headers, ever.
    return csrf_exempt(require_POST(never_cache(xframe_options_deny(view))))


def _is_cross_site(request) -> bool:
    # WHY only cross-site: browsers' DBSC fetches send same-origin or same-site, and older clients send nothing.
    return request.headers.get("Sec-Fetch-Site") == "cross-site"


def _bound_response(sid: str, next_challenge: str) -> JsonResponse:
    response = JsonResponse(session_instructions(sid))
    max_age = conf.get("BOUND_COOKIE_MAX_AGE")
    set_bound_cookie(response, BoundCookieCodec(max_age=max_age).encode(sid), max_age=max_age)
    response.headers[CHALLENGE_HEADER] = challenge_header(challenge=next_challenge, session_identifier=sid)
    return response


@dbsc_endpoint
def register_view(request):
    if _is_cross_site(request):
        logger.warning("[DBSC] register rejected: cross-site request path=%s", request.path)
        return HttpResponse(status=403)
    try:
        registration = get_registration_service().register(
            django_session=request.session,
            user=getattr(request, "user", None),
            proof_token=request.headers.get(RESPONSE_HEADER),
        )
    except RegistrationError as exc:
        logger.warning("[DBSC] register rejected: status=%s reason=%s", exc.status, exc.reason)
        # The detailed reason only goes to the log, so callers can't use the response to probe the checks.
        return HttpResponse(status=exc.status)

    sid = registration.session_identifier
    logger.info("[DBSC] session bound user_id=%s dbsc_id=%s alg=%s", request.user.pk, sid, registration.alg)
    return _bound_response(sid, registration.refresh_challenge)


@dbsc_endpoint
def refresh_view(request):
    if _is_cross_site(request):
        logger.warning("[DBSC] refresh rejected: cross-site request path=%s", request.path)
        return HttpResponse(status=403)
    try:
        refreshed = get_refresh_service().refresh(
            django_session=request.session,
            user=getattr(request, "user", None),
            session_id=request.headers.get(SESSION_ID_HEADER),
            proof_token=request.headers.get(RESPONSE_HEADER),
        )
    except ChallengeRequired as exc:
        logger.info("[DBSC] refresh needs challenge dbsc_id=%s reason=%s", exc.session_identifier, exc.reason)
        response = HttpResponse(status=403)
        response.headers[CHALLENGE_HEADER] = challenge_header(
            challenge=exc.challenge, session_identifier=exc.session_identifier
        )
        return response
    except RefreshError as exc:
        logger.warning(
            "[DBSC] refresh terminated status=%s reason=%s dbsc_id=%s",
            exc.status,
            exc.reason,
            request.headers.get(SESSION_ID_HEADER),
        )
        return HttpResponse(status=exc.status)
    except DatabaseError:
        # WHY 503 and not 4xx: a 4xx makes the browser terminate the session, logging users out over a DB hiccup.
        logger.exception("[DBSC] refresh backend failure dbsc_id=%s", request.headers.get(SESSION_ID_HEADER))
        return HttpResponse(status=503, headers={"Retry-After": "5"})

    return _bound_response(refreshed.session_identifier, refreshed.next_challenge)
