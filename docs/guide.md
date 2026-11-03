# User guide

This guide assumes you've done the [Quickstart](../README.md#quickstart). It explains what happens after login, how to
choose a protection mode, and what to check before deploying.

- [What happens after login](#what-happens-after-login)
- [Choosing a protection mode](#choosing-a-protection-mode)
- [Checking binding in your own code](#checking-binding-in-your-own-code)
- [Logging out and revoking devices](#logging-out-and-revoking-devices)
- [Deployment checklist](#deployment-checklist)
- [Local development over HTTPS](#local-development-over-https)
- [Logging](#logging)

## What happens after login

You don't call anything. When `django.contrib.auth.login()` runs (your own view, `LoginView`, django-allauth, …),
django-dbsc does the following:

```
1. Login response (200 or 302)   + Secure-Session-Registration header       ← added by the middleware
2. Browser, in the background    POST /dbsc/register   (signed with a new device key)
3. Server                         stores the public key, sets the short-lived "dbsc_bound" cookie
4. Every later request            must carry a valid dbsc_bound cookie, or it gets 401
5. Shortly before it expires      the browser refreshes it: POST /dbsc/refresh (signed again)
```

Two things follow from this:

- **The first page after login is not bound yet.** Registration runs in the background, so the page your login
  redirects to usually loads before it finishes. Don't put `@device_bound_required` on your post-login landing page.
- **Browsers without DBSC simply never register.** Their sessions behave exactly as they would without django-dbsc.

## Choosing a protection mode

django-dbsc protects at three levels. You can combine them.

| Mode | What it does | Users without DBSC | Configure with |
|---|---|---|---|
| **A. Opportunistic** (default) | Bound sessions are protected. Unbound ones work as before. | unaffected | nothing |
| **B. Step-up for sensitive views** | Chosen views need a proven device. Unbound sessions are sent to re-authentication or refused. | can't use those views without step-up | `@device_bound_required`, `STEP_UP_URL` |
| **C. Required binding** | Chosen users *must* bind within a grace period, or are logged out. | locked out (for those users) | `REQUIRE_BINDING` |

### A. Opportunistic (default)

Nothing to configure. Once a session is bound, the binding is enforced on every request. An attacker can't downgrade
it by switching to a browser without DBSC, because the server remembers that the session is bound.

What it doesn't protect: sessions that never got bound, such as every Firefox or Safari user today.

### B. Step-up for sensitive views

Decorate the views where cookie theft would hurt most:

```python
from django.contrib.auth.decorators import login_required
from django_dbsc.decorators import device_bound_required


@login_required
@device_bound_required
def payout_settings(request): ...
```

For class-based views, use `method_decorator`:

```python
from django.utils.decorators import method_decorator


@method_decorator(device_bound_required, name="dispatch")
class PayoutSettingsView(LoginRequiredMixin, UpdateView): ...
```

An unbound request gets `403` by default. To send it to a re-authentication page instead (for example a password or
MFA prompt), set `STEP_UP_URL`. The user is redirected there with `?next=<original URL>`:

```python
DJANGO_DBSC = {
    "STEP_UP_URL": "/accounts/reauth/",
}
```

Put `@login_required` first (outermost), so anonymous users are sent to login rather than to step-up.

### C. Required binding

For accounts where an unbound session is not acceptable, such as staff or admins:

```python
DJANGO_DBSC = {
    "REQUIRE_BINDING": "django_dbsc.policies.staff_only",
    "BINDING_GRACE_SECONDS": 30,
}
```

How it behaves:

1. A matching user logs in and their session is "pending". They can browse normally for `BINDING_GRACE_SECONDS`.
   That gives the background registration time to finish.
2. If the session is bound within that time, nothing else happens.
3. If it's still unbound afterwards, the next request is answered with `403` and the session is ended.

Built-in policies, all in `django_dbsc.policies`:

| Policy | Requires binding for |
|---|---|
| `staff_only` | `user.is_staff` |
| `superusers_only` | `user.is_superuser` |
| `everyone` | all authenticated users. ⚠️ This locks out every browser without DBSC support. |

Or write your own. Any callable `(user) -> bool` works, given as a dotted path or the function itself:

```python
# myproject/dbsc_policy.py
def finance_team(user):
    return user.groups.filter(name="finance").exists()
```

```python
DJANGO_DBSC = {"REQUIRE_BINDING": "myproject.dbsc_policy.finance_team"}
```

Things to know:

- **Rolling it out is safe for existing sessions.** Sessions created before you enabled the policy get their grace
  period from the first request seen afterwards, not from their original login.
- **Users on unsupported browsers get logged out after the grace period.** They will keep being logged out at every
  login. Tell those users in advance which browser they need.
- An invalid dotted path makes Django fail at startup (`ImproperlyConfigured`), not on the first request.

## Checking binding in your own code

The middleware sets `request.dbsc_bound` on every request:

```python
def dashboard(request):
    if request.dbsc_bound:
        ...  # this request proved possession of the device key
    else:
        ...  # unbound: unsupported browser, registration still running, or binding not required
```

It is `True` only if the session is bound **and** the request carries a valid bound cookie for that binding.

`@device_bound_required` raises `ImproperlyConfigured` if the middleware is missing. It fails closed rather than
assuming the request is fine.

## Logging out and revoking devices

**Logout** is handled for you. Any call to `django.contrib.auth.logout()` revokes the current device's binding and
clears its cookie. The user's other devices stay signed in.

**Revoking all devices of a user**, for example after a password change or a suspected compromise:

```python
from django_dbsc.repositories import DeviceBoundSessionRepository

DeviceBoundSessionRepository().revoke_all_for_user(user, reason="password_changed")
```

How quickly a revocation takes effect: within `BOUND_COOKIE_MAX_AGE` (10 minutes by default). The bound cookie is
checked without a database lookup, so the device keeps working until its current cookie expires. Its next refresh is
then refused, and the session ends. To cut access off immediately, also end the user's Django sessions.

**Audit trail:** bindings are never deleted, only marked revoked. Each `DeviceBoundSession` row records
`created_at`, `last_refreshed_at`, `revoked_at` and `revoked_reason`:

| `revoked_reason` | Set when |
|---|---|
| `logout` | the user logged out |
| `replaced` | the user logged in again in the same session, and the new binding replaced the old one |
| `missing_bound_cookie` | a request on a bound session arrived without a valid bound cookie (e.g. a stolen `sessionid`) |
| your own string | you called `revoke()` or `revoke_all_for_user()` with a `reason` |

The first reason is kept. A later revocation never overwrites it.

## Deployment checklist

- [ ] **HTTPS everywhere.** Browsers only use DBSC on secure origins.
- [ ] **Shared cache.** Challenges are stored in Django's `default` cache. With several workers or servers it must be
      shared (Redis, Memcached, database cache). Otherwise refreshes fail with `403` loops.
- [ ] **Middleware order:** `DeviceBoundSessionMiddleware` after `SessionMiddleware` and `AuthenticationMiddleware`.
- [ ] **Exempt paths:** `EXEMPT_PATH_PREFIXES` contains the DBSC URL prefix and your static/media prefixes.
- [ ] **If you mount the URLs elsewhere than `/dbsc/`,** update `REGISTRATION_PATH`, `REFRESH_URL` and
      `EXEMPT_PATH_PREFIXES` together.
- [ ] **`BOUND_COOKIE_MAX_AGE` ≥ 300.** Shorter values exhaust the browser's signing quota. `manage.py check` warns
      (`django_dbsc.W001`).
- [ ] **No CORS credentials on `/dbsc/`.** Don't let a CORS middleware add `Access-Control-Allow-Credentials` to the
      DBSC endpoints.
- [ ] **Your reverse proxy forwards** the `Secure-Session-*`, `Sec-Secure-Session-Id` and `Sec-Fetch-Site`
      request headers, and doesn't strip `Secure-Session-*` response headers.

## Local development over HTTPS

Chrome ignores DBSC on `http://localhost`. You need a trusted certificate locally, for example with
[mkcert](https://github.com/FiloSottile/mkcert):

```bash
mkcert -install && mkcert localhost
uv run --with gunicorn gunicorn myproject.wsgi --bind 127.0.0.1:8443 \
  --certfile localhost.pem --keyfile localhost-key.pem
```

On macOS, DBSC may still be switched off in your Chrome by the gradual rollout. To force it on for testing, start a
separate Chrome profile:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --user-data-dir=/tmp/dbsc-profile \
  --enable-features=DeviceBoundSessions,UseUnexportableKeyServiceInBrowserProcess,PersistDeviceBoundSessions
```

The `example/` directory has a complete demo project, with scripts that drive Chrome and print its DBSC events. See
[real-browser-testing.md](real-browser-testing.md).

## Logging

Everything is logged to the `django_dbsc` logger, with the prefix `[DBSC]`:

| Level | Event |
|---|---|
| `INFO` | session bound, refresh challenge issued, refresh skipped by browser, binding revoked on logout, unbound session refused by the decorator |
| `WARNING` | register or refresh rejected (with reason), missing or invalid bound cookie (possible cookie theft), binding required but missing after grace |
| `ERROR` | revocation or refresh failed because of a database error |

A spike of `bound cookie missing/invalid, ending session` warnings is the signal to watch: it's what a stolen session
cookie looks like.

```python
LOGGING = {
    "version": 1,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"django_dbsc": {"handlers": ["console"], "level": "INFO"}},
}
```
