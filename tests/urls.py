from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from django.urls import include, path
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from django_dbsc.decorators import device_bound_required


@csrf_exempt  # test fixture: lets CSRF-enforcing clients log in. The DBSC endpoints are what's under test.
@require_POST
def login_view(request):
    user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
    if user is None:
        return HttpResponse("bad credentials", status=401)
    login(request, user)
    return HttpResponse("welcome")


def bound_status_view(request):
    return HttpResponse(str(request.dbsc_bound))


@device_bound_required
def sensitive_view(request):
    return HttpResponse("sensitive")


urlpatterns = [
    path("protected/", lambda request: HttpResponse("ok"), name="protected"),
    path("bound-status/", bound_status_view, name="bound-status"),
    path("sensitive/", sensitive_view, name="sensitive"),
    path("login/", login_view, name="login"),
    path("dbsc/", include("django_dbsc.urls")),
]
