import logging

from django.db import DatabaseError
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist

from django_dbsc import conf
from django_dbsc.constants import (
    BOUND_COOKIE_NAME,
    CHALLENGE_HEADER,
    SESSION_CHALLENGE_PENDING,
    SESSION_DBSC_ID,
    SKIPPED_HEADER,
)
from django_dbsc.repositories import DeviceBoundSessionRepository
from django_dbsc.services.challenge import ChallengeStore, refresh_challenges, refresh_scope, registration_challenges
from django_dbsc.services.cookie import BoundCookieCodec
from django_dbsc.services.headers import challenge_header
from django_dbsc.services.logout import clear_bound_cookie
from django_dbsc.services.policy import BindingPolicy, Verdict, load_policy
from django_dbsc.services.registration import offer_registration
from django_dbsc.services.skipped import names_session

logger = logging.getLogger("django_dbsc")


class DeviceBoundSessionMiddleware:
    """Requires a valid bound cookie on every request of a DBSC-bound session, and offers registration after login.

    Must come after SessionMiddleware and AuthenticationMiddleware.
    """

    def __init__(
        self,
        get_response,
        cookie_codec: BoundCookieCodec | None = None,
        challenges: ChallengeStore | None = None,
        policy: BindingPolicy | None = None,
        repo: DeviceBoundSessionRepository | None = None,
        refresh_challenge_store: ChallengeStore | None = None,
    ):
        self.get_response = get_response
        self.codec = cookie_codec or BoundCookieCodec(max_age=conf.get("BOUND_COOKIE_MAX_AGE"))
        self.challenges = challenges or registration_challenges()
        self.refresh_challenges = refresh_challenge_store or refresh_challenges()
        self.repo = repo or DeviceBoundSessionRepository()
        self.exempt_prefixes = tuple(conf.get("EXEMPT_PATH_PREFIXES"))
        # Loaded once at startup, so a bad REQUIRE_BINDING path fails at boot rather than on a request.
        self.policy = policy or load_policy(conf.get("REQUIRE_BINDING"), conf.get("BINDING_GRACE_SECONDS"))

    def __call__(self, request):
        dbsc_id = request.session.get(SESSION_DBSC_ID)
        # WHY the session binding *and* the cookie: the cookie alone could be replayed into another session, and the
        # binding alone is exactly what a stolen sessionid carries.
        request.dbsc_bound = bool(dbsc_id) and self.codec.is_valid(request.COOKIES.get(BOUND_COOKIE_NAME), dbsc_id)
        exempt = request.path.startswith(self.exempt_prefixes)
        if dbsc_id and not request.dbsc_bound and not exempt:
            return self._reject(request, dbsc_id)
        if not dbsc_id and not exempt and self.policy.evaluate(request.session, request.user) is Verdict.VIOLATION:
            return self._reject_unbound(request)
        response = self.get_response(request)
        offer_registration(request, response, self.challenges)
        if request.dbsc_bound and not exempt:
            self._send_first_refresh_challenge(request, response, dbsc_id)
        clear_bound_cookie(request, response)
        return response

    def _reject(self, request, dbsc_id: str) -> HttpResponse:
        skipped = request.headers.get(SKIPPED_HEADER)
        if names_session(skipped, dbsc_id):
            # WHY refuse but keep the session: real browsers skip refreshes (signing quota, unreachable endpoint)
            # and say so. The header is forgeable, so it never grants access. A thief still gets a 401 and has no
            # key to refresh with, while the real browser recovers on its next successful refresh.
            logger.info("[DBSC] refresh skipped by browser, refusing without ending session dbsc_id=%s", dbsc_id)
            return HttpResponse("Device-bound session could not be verified.", status=401)

        logger.warning(
            "[DBSC] bound cookie missing/invalid, ending session dbsc_id=%s path=%s skipped=%r",
            dbsc_id,
            request.path,
            skipped,
        )
        self._revoke(dbsc_id, reason="missing_bound_cookie")
        request.session.flush()
        response = HttpResponse("Device-bound session could not be verified.", status=401)
        response.delete_cookie(BOUND_COOKIE_NAME)
        return response

    def _reject_unbound(self, request) -> HttpResponse:
        logger.warning(
            "[DBSC] binding required but session still unbound after grace, ending session user_id=%s path=%s",
            request.user.pk,
            request.path,
        )
        # WHY flush before redirecting: the target page then sees an anonymous session, so it can't loop back here.
        request.session.flush()
        url = conf.get("BINDING_REQUIRED_URL")
        if url:
            return HttpResponseRedirect(url)
        try:
            return render(request, "django_dbsc/binding_required.html", status=403)
        except TemplateDoesNotExist:
            # Projects without a template engine (pure APIs) still get a clean 403, never a 500.
            return HttpResponseForbidden("This account requires a browser that supports device-bound sessions.")

    def _revoke(self, dbsc_id: str, reason: str) -> None:
        # WHY revoke as well as flush: otherwise the binding lingers as an "active" record for a dead session.
        try:
            self.repo.revoke(dbsc_id, reason=reason)
        except DatabaseError:
            # The 401 and the flush still protect the session, so a DB hiccup must not turn this into a 500.
            logger.exception("[DBSC] could not revoke binding dbsc_id=%s reason=%s", dbsc_id, reason)

    def _send_first_refresh_challenge(self, request, response, dbsc_id: str) -> None:
        # WHY: Chrome appears to ignore the challenge on the register response, because the session it names doesn't
        # exist on Chrome's side yet. Without a cached challenge its first refresh costs a 403 retry. Once the browser
        # sends the bound cookie, it knows the session, so a challenge here gets cached.
        if request.session.pop(SESSION_CHALLENGE_PENDING, False):
            challenge = self.refresh_challenges.issue(refresh_scope(dbsc_id))
            response.headers[CHALLENGE_HEADER] = challenge_header(challenge=challenge, session_identifier=dbsc_id)
