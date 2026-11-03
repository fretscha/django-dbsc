from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.urls import include, path

from django_dbsc.decorators import device_bound_required
from django_dbsc.services.registration import request_registration_offer


@login_required
def protected(request):
    return HttpResponse(f"protected ok user={request.user.username} dbsc_bound={request.dbsc_bound}")


@login_required
@device_bound_required
def sensitive(request):
    return HttpResponse("sensitive ok")


@login_required
def offer(request):
    """Diagnostic: send the registration offer on a plain 200 (not on the login redirect)."""
    request_registration_offer(sender=None, request=request, user=request.user)
    return HttpResponse("offer sent")


VARIANTS = {
    "ours": ("Secure-Session-Registration", '(ES256 RS256);path="/dbsc/register";challenge="c"'),
    "single-alg": ("Secure-Session-Registration", '(ES256);path="/dbsc/register";challenge="c"'),
    "absolute": ("Secure-Session-Registration", '(ES256);path="http://localhost:8765/dbsc/register";challenge="c"'),
    "legacy-name": ("Sec-Session-Registration", '(ES256);path="/dbsc/register";challenge="c"'),
}


def variant(request, name):
    """Diagnostic: raw registration header variants, to find which format this Chrome accepts."""
    header, value = VARIANTS[name]
    response = HttpResponse(f"variant {name}")
    response.headers[header] = value
    return response


urlpatterns = [
    path("variant/<str:name>/", variant),
    path("offer/", offer),
    path("accounts/login/", auth_views.LoginView.as_view(), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("protected/", protected),
    path("sensitive/", sensitive),
    path("dbsc/", include("django_dbsc.urls")),
]
