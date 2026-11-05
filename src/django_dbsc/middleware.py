import logging
from inspect import iscoroutinefunction, markcoroutinefunction

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
from django_dbsc.services.registration import aoffer_registration, offer_registration
from django_dbsc.services.skipped import names_session

logger = logging.getLogger("django_dbsc")

REJECTED_MESSAGE = "Device-bound session could not be verified."


class DeviceBoundSessionMiddleware:
    """Requires a valid bound cookie on every request of a DBSC-bound session, and offers registration after login.

    Must come after SessionMiddleware and AuthenticationMiddleware. Works under WSGI and natively under ASGI: the
    async path uses Django's async session, user, cache and ORM APIs, so it never blocks the event loop.
    """

    sync_capable = True
    async_capable = True

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
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)

    def __call__(self, request):
        if iscoroutinefunction(self):
            return self.__acall__(request)
        dbsc_id = request.session.get(SESSION_DBSC_ID)
        exempt = self._check_bound(request, dbsc_id)
        if dbsc_id and not request.dbsc_bound and not exempt:
            return self._reject(request, dbsc_id)
        if not dbsc_id and not exempt and self.policy.evaluate(request.session, request.user) is Verdict.VIOLATION:
            return self._reject_unbound(request, request.user.pk)
        response = self.get_response(request)
        offer_registration(request, response, self.challenges)
        if request.dbsc_bound and not exempt and request.session.pop(SESSION_CHALLENGE_PENDING, False):
            self._attach_challenge(response, dbsc_id, self.refresh_challenges.issue(refresh_scope(dbsc_id)))
        clear_bound_cookie(request, response)
        return response

    async def __acall__(self, request):
        dbsc_id = await request.session.aget(SESSION_DBSC_ID)
        exempt = self._check_bound(request, dbsc_id)
        if dbsc_id and not request.dbsc_bound and not exempt:
            return await self._areject(request, dbsc_id)
        if (
            not dbsc_id
            and not exempt
            and await self.policy.aevaluate(request.session, request.auser) is Verdict.VIOLATION
        ):
            user = await request.auser()
            return await self._areject_unbound(request, user.pk)
        response = await self.get_response(request)
        await aoffer_registration(request, response, self.challenges)
        if request.dbsc_bound and not exempt and await request.session.apop(SESSION_CHALLENGE_PENDING, False):
            self._attach_challenge(response, dbsc_id, await self.refresh_challenges.aissue(refresh_scope(dbsc_id)))
        clear_bound_cookie(request, response)
        return response

    # --- shared, I/O-free steps -----------------------------------------------------------------------------------

    def _check_bound(self, request, dbsc_id: str | None) -> bool:
        """Sets request.dbsc_bound and returns whether the path is exempt."""
        # WHY the session binding *and* the cookie: the cookie alone could be replayed into another session, and the
        # binding alone is exactly what a stolen sessionid carries.
        request.dbsc_bound = bool(dbsc_id) and self.codec.is_valid(request.COOKIES.get(BOUND_COOKIE_NAME), dbsc_id)
        return request.path.startswith(self.exempt_prefixes)

    @staticmethod
    def _skipped_by_browser(request, dbsc_id: str) -> bool:
        if not names_session(request.headers.get(SKIPPED_HEADER), dbsc_id):
            return False
        # WHY refuse but keep the session: real browsers skip refreshes (signing quota, unreachable endpoint) and say
        # so. The header is forgeable, so it never grants access. A thief still gets a 401 and has no key to refresh
        # with, while the real browser recovers on its next successful refresh.
        logger.info("[DBSC] refresh skipped by browser, refusing without ending session dbsc_id=%s", dbsc_id)
        return True

    @staticmethod
    def _log_rejection(request, dbsc_id: str) -> None:
        logger.warning(
            "[DBSC] bound cookie missing/invalid, ending session dbsc_id=%s path=%s skipped=%r",
            dbsc_id,
            request.path,
            request.headers.get(SKIPPED_HEADER),
        )

    @staticmethod
    def _rejected_response() -> HttpResponse:
        response = HttpResponse(REJECTED_MESSAGE, status=401)
        response.delete_cookie(BOUND_COOKIE_NAME)
        return response

    @staticmethod
    def _log_unbound(request, user_pk) -> None:
        logger.warning(
            "[DBSC] binding required but session still unbound after grace, ending session user_id=%s path=%s",
            user_pk,
            request.path,
        )

    @staticmethod
    def _binding_required_response(request) -> HttpResponse:
        url = conf.get("BINDING_REQUIRED_URL")
        if url:
            return HttpResponseRedirect(url)
        try:
            return render(request, "django_dbsc/binding_required.html", status=403)
        except TemplateDoesNotExist:
            # Projects without a template engine (pure APIs) still get a clean 403, never a 500.
            return HttpResponseForbidden("This account requires a browser that supports device-bound sessions.")

    @staticmethod
    def _attach_challenge(response, dbsc_id: str, challenge: str) -> None:
        # WHY: Chrome ignores the challenge on the register response, because the session it names doesn't exist on
        # Chrome's side yet. Without a cached challenge its first refresh costs a 403 retry. Once the browser sends
        # the bound cookie it knows the session, so a challenge on that response gets cached.
        response.headers[CHALLENGE_HEADER] = challenge_header(challenge=challenge, session_identifier=dbsc_id)

    # --- sync I/O ---------------------------------------------------------------------------------------------------

    def _reject(self, request, dbsc_id: str) -> HttpResponse:
        if self._skipped_by_browser(request, dbsc_id):
            return HttpResponse(REJECTED_MESSAGE, status=401)
        self._log_rejection(request, dbsc_id)
        try:
            # WHY revoke as well as flush: otherwise the binding lingers as an "active" record for a dead session.
            self.repo.revoke(dbsc_id, reason="missing_bound_cookie")
        except DatabaseError:
            # The 401 and the flush still protect the session, so a DB hiccup must not turn this into a 500.
            logger.exception("[DBSC] could not revoke binding dbsc_id=%s", dbsc_id)
        request.session.flush()
        return self._rejected_response()

    def _reject_unbound(self, request, user_pk) -> HttpResponse:
        self._log_unbound(request, user_pk)
        # WHY flush before redirecting: the target page then sees an anonymous session, so it can't loop back here.
        request.session.flush()
        return self._binding_required_response(request)

    # --- async I/O --------------------------------------------------------------------------------------------------

    async def _areject(self, request, dbsc_id: str) -> HttpResponse:
        if self._skipped_by_browser(request, dbsc_id):
            return HttpResponse(REJECTED_MESSAGE, status=401)
        self._log_rejection(request, dbsc_id)
        try:
            await self.repo.arevoke(dbsc_id, reason="missing_bound_cookie")
        except DatabaseError:
            logger.exception("[DBSC] could not revoke binding dbsc_id=%s", dbsc_id)
        await request.session.aflush()
        return self._rejected_response()

    async def _areject_unbound(self, request, user_pk) -> HttpResponse:
        self._log_unbound(request, user_pk)
        await request.session.aflush()
        return self._binding_required_response(request)
