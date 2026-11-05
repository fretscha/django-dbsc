import logging

logger = logging.getLogger("demo.probe")

WATCHED = (
    "Sec-Fetch-Site",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Dest",
    "Sec-Secure-Session-Id",
    "Secure-Session-Skipped",
)


class DbscProbeMiddleware:
    """Logs every request with the DBSC-relevant headers, plus response status and the DBSC headers we sent."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.endswith("/dbsc/refresh"):
            self._log_challenge_state(request)
        response = self.get_response(request)
        seen = {h: request.headers[h] for h in WATCHED if h in request.headers}
        if "Secure-Session-Response" in request.headers:
            seen["Secure-Session-Response"] = "<jwt>"
        sent = [h for h in ("Secure-Session-Registration", "Secure-Session-Challenge") if h in response.headers]
        logger.info(
            "[PROBE] %s %s -> %s bound_cookie=%s req=%s sent=%s",
            request.method,
            request.get_full_path(),
            response.status_code,
            "dbsc_bound" in request.COOKIES,
            seen,
            sent,
        )
        return response

    @staticmethod
    def _log_challenge_state(request) -> None:
        """Diagnostics: which challenge did the browser sign, and which does the server consider active?"""
        import jwt

        from django_dbsc.services.challenge import refresh_challenges, refresh_scope

        sid = request.headers.get("Sec-Secure-Session-Id", "")
        token = request.headers.get("Secure-Session-Response")
        jti = jwt.decode(token, options={"verify_signature": False}).get("jti", "") if token else ""
        active = refresh_challenges().active(refresh_scope(sid))
        logger.info(
            "[PROBE] refresh signed jti=%s in_active=%s active=%s",
            jti[:8] or "-",
            jti in active,
            sorted(c[:8] for c in active),
        )
