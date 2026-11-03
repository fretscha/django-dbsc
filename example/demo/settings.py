"""Demo project for manual and real-browser testing of django-dbsc. Not for production use."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "demo-only-not-secret"
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
USE_TZ = True
ROOT_URLCONF = "demo.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_REDIRECT_URL = "/protected/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "django_dbsc",
]

MIDDLEWARE = [
    "demo.probe.DbscProbeMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_dbsc.middleware.DeviceBoundSessionMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "demo" / "templates"],
        "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
    }
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "demo.sqlite3"}}
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "demo" / "static"]

DJANGO_DBSC = {
    "EXEMPT_PATH_PREFIXES": ["/dbsc/", "/static/"],
    # Chrome refreshes proactively when <2 min remain and allows only ~2 signings per 3-5 min, so lifetimes much
    # below 5 min get refreshes skipped with Secure-Session-Skipped: quota_exceeded. Found in real-browser testing.
    # Override to reproduce the quota behaviour, e.g. DBSC_BOUND_COOKIE_MAX_AGE=20 (this triggers check W001).
    "BOUND_COOKIE_MAX_AGE": int(os.environ.get("DBSC_BOUND_COOKIE_MAX_AGE", "600")),
}

LOGGING = {
    "version": 1,
    "formatters": {"ts": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "ts"}},
    "loggers": {
        "django_dbsc": {"handlers": ["console"], "level": "DEBUG"},
        "demo.probe": {"handlers": ["console"], "level": "INFO"},
        "django": {"handlers": ["console"], "level": "ERROR"},
    },
}
