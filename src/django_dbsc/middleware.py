import logging

from django.http import HttpResponse, HttpResponseForbidden

from django_dbsc import conf
from django_dbsc.constants import BOUND_COOKIE_NAME, SESSION_DBSC_ID
from django_dbsc.services.challenge import ChallengeStore
from django_dbsc.services.cookie import BoundCookieCodec
from django_dbsc.services.policy import BindingPolicy, Verdict, load_policy
from django_dbsc.services.registration import offer_registration

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
    ):
        self.get_response = get_response
        self.codec = cookie_codec or BoundCookieCodec(max_age=conf.get("BOUND_COOKIE_MAX_AGE"))
        self.challenges = challenges or ChallengeStore()
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
        return response

    def _reject(self, request, dbsc_id: str) -> HttpResponse:
        # WHY we never honour Secure-Session-Skipped: it is a client header, so a cookie thief can send it too.
        logger.warning(
            "[DBSC] bound cookie missing/invalid, ending session dbsc_id=%s path=%s skipped=%r",
            dbsc_id,
            request.path,
            request.headers.get("Secure-Session-Skipped"),
        )
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
        request.session.flush()
        return HttpResponseForbidden("This account requires a browser that supports device-bound sessions.")
