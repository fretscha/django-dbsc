# django-dbsc

[![CI](https://github.com/fretscha/django-dbsc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fretscha/django-dbsc/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Ffretscha%2Fdjango-dbsc%2Fbadges%2Fcoverage.json)](https://github.com/fretscha/django-dbsc/actions/workflows/badges.yml)

**Stolen session cookies stop working.** django-dbsc adds [Device Bound Session Credentials
(DBSC)](https://w3c.github.io/webappsec-dbsc/) to Django: after login, the browser binds the session to a private key
that never leaves the device (TPM or Secure Enclave). An attacker who copies the `sessionid` cookie with malware or an
infostealer gets a `401`, because they can't prove they hold that key.

```
Without DBSC:  stolen sessionid  ──▶  attacker is logged in as the victim
With DBSC:     stolen sessionid  ──▶  401 (no device key, no valid bound cookie)
```

- **Drop-in:** one app, one middleware, two URLs. Your login and logout views stay as they are.
- **Graceful:** browsers without DBSC support keep working exactly as before.
- **Your choice of strictness:** protect everyone opportunistically, guard sensitive views, or *require* binding for
  staff.

> **Status: alpha (0.1.0).** It has been verified end to end in Chrome 156 (see
> [docs/real-browser-testing.md](https://github.com/fretscha/django-dbsc/blob/main/docs/real-browser-testing.md)). The API may still change before 1.0. See the
> [CHANGELOG](https://github.com/fretscha/django-dbsc/blob/main/CHANGELOG.md) for known limitations.

## Requirements

- Python ≥ 3.12, Django ≥ 5.2
- **HTTPS**, including in local development. Chrome ignores DBSC on plain `http://`, even on `localhost`.
- **A cache shared by all processes** (Redis, Memcached or the database cache). The default per-process `LocMemCache`
  breaks with more than one worker.

## Quickstart

```bash
uv add "django-dbsc>=0.1.0"        # or: pip install "django-dbsc>=0.1.0"
```

(0.0.1 on PyPI is an empty name placeholder. Make sure you get 0.1.0 or later.)

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "django_dbsc",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_dbsc.middleware.DeviceBoundSessionMiddleware",  # after Session and Authentication middleware
    # ...
]

DJANGO_DBSC = {
    # Paths the browser must reach without a bound cookie. Always keep the DBSC endpoints here.
    "EXEMPT_PATH_PREFIXES": ["/dbsc/", "/static/"],
}
```

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    # ...
    path("dbsc/", include("django_dbsc.urls")),
]
```

```bash
python manage.py migrate
```

That's it. Every login now offers the browser a device binding, and bound sessions are protected automatically.

To require a proven device for a sensitive view:

```python
from django.contrib.auth.decorators import login_required
from django_dbsc.decorators import device_bound_required


@login_required
@device_bound_required
def change_password(request): ...
```

## Documentation

| Read this | If you want to |
|---|---|
| [User guide](https://github.com/fretscha/django-dbsc/blob/main/docs/guide.md) | understand the three protection modes, use `request.dbsc_bound` and the decorator, revoke devices, deploy |
| [Configuration](https://github.com/fretscha/django-dbsc/blob/main/docs/configuration.md) | look up a setting, its default and when to change it |
| [How it works & security model](https://github.com/fretscha/django-dbsc/blob/main/docs/security.md) | know exactly what is and isn't protected |
| [Troubleshooting](https://github.com/fretscha/django-dbsc/blob/main/docs/troubleshooting.md) | find out why a browser doesn't bind, or why users get logged out |

## Browser support

DBSC is a W3C draft. At the time of writing:

| Browser | Status |
|---|---|
| Chrome on Windows | Enabled by default since Chrome 145 (needs a TPM) |
| Chrome on macOS | Since Chrome 147, rolling out gradually (Secure Enclave) |
| Firefox, Safari | Not supported. Sessions work as before, without binding. |

You don't need to detect support. Browsers without DBSC ignore the registration offer.

## License

[MIT](https://github.com/fretscha/django-dbsc/blob/main/LICENSE)
