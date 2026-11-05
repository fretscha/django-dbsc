import functools
import logging
from inspect import iscoroutinefunction

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden

from django_dbsc import conf

logger = logging.getLogger("django_dbsc")


def device_bound_required(view):
    """Only let the request through if it proved possession of the session's device key.

    Unbound sessions, including browsers without DBSC support, go to ``STEP_UP_URL`` when one is configured.
    Otherwise they get a 403. Works for sync and async views.
    """
    if iscoroutinefunction(view):

        @functools.wraps(view)
        async def async_wrapper(request, *args, **kwargs):
            if _is_bound(request):
                return await view(request, *args, **kwargs)
            user = await request.auser() if hasattr(request, "auser") else None
            return _refuse(request, user)

        return async_wrapper

    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        if _is_bound(request):
            return view(request, *args, **kwargs)
        return _refuse(request, getattr(request, "user", None))

    return wrapper


def _is_bound(request) -> bool:
    if not hasattr(request, "dbsc_bound"):
        # Fail closed: nothing verified the bound cookie, so we can't vouch for this request.
        raise ImproperlyConfigured(
            "device_bound_required needs django_dbsc.middleware.DeviceBoundSessionMiddleware in MIDDLEWARE."
        )
    return request.dbsc_bound


def _refuse(request, user):
    user_id = user.pk if user is not None and user.is_authenticated else None
    logger.info("[DBSC] unbound session refused path=%s user_id=%s", request.path, user_id)
    step_up_url = conf.get("STEP_UP_URL")
    if step_up_url:
        return redirect_to_login(request.get_full_path(), login_url=step_up_url)
    return HttpResponseForbidden("This action requires a device-bound session.")
