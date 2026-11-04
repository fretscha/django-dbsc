# Troubleshooting

Start with the logs: everything is on the `django_dbsc` logger with a `[DBSC]` prefix (see
[Logging](guide.md#logging)). Browsers fail DBSC **silently**, so the server log and Chrome's DevTools are your only
windows into what happened.

## The browser never binds (no `POST /dbsc/register` in the logs)

Check, in this order:

1. **Is the site on HTTPS?** Chrome ignores DBSC on `http://`, even on `localhost`.
2. **Does the login response carry the header?** Look for `Secure-Session-Registration` in the response headers. If
   it's missing:
   - the middleware isn't installed, or sits before `SessionMiddleware`/`AuthenticationMiddleware`
   - `django_dbsc` isn't in `INSTALLED_APPS`, so the login signal isn't connected
   - your login doesn't go through `django.contrib.auth.login()`
3. **Is DBSC enabled in this browser?** Firefox and Safari don't support it. On macOS, Chrome rolls it out gradually,
   so it may be off. Open `chrome://version/?show-variations-cmd` and look for `DeviceBoundSessions`. To force it on
   for testing, see [Local development over HTTPS](guide.md#local-development-over-https).
4. **Does `REGISTRATION_PATH` match where you mounted `django_dbsc.urls`?**
5. **Does the device have a TPM or Secure Enclave?** Without one, Chrome can't create the key, and says nothing.

To see Chrome's own reason codes (e.g. `SigningQuotaExceeded`, `InvalidCredentialsCookie`), run
`example/scripts/trace_dbsc_events.py`. It reads them from Chrome's DevTools protocol.

## Registration is rejected (`register rejected` in the logs)

| Logged reason | Cause |
|---|---|
| `status=401 reason=not authenticated` | The registration request arrived without a logged-in session. Check that the session cookie reaches `/dbsc/register`. |
| `invalid proof: unknown or expired challenge` | More than 120 s passed between login and registration, or the cache isn't shared between workers. |
| `challenge already used` | Two registrations raced for one login. Harmless. |
| `cross-site request` | The request had `Sec-Fetch-Site: cross-site`. Check proxies and domains. |

## Users get logged out unexpectedly

Look for `bound cookie missing/invalid, ending session` in the logs.

- **The bound cookie's attributes were changed** by a proxy or a middleware (domain, path, `SameSite`). The browser
  then can't match the cookie, and refreshes in a loop.
- **The browser skipped refreshes.** The logs say `refresh skipped by browser`. These requests get `401` but keep the
  session, and they recover by themselves. If you see many of them, `BOUND_COOKIE_MAX_AGE` is too low (see
  `manage.py check`, warning `django_dbsc.W001`).
- **`SECRET_KEY` changed or differs between servers.** All bound cookies become invalid at once.
- **It really is cookie theft.** A single user's session is ended from an unfamiliar IP or user agent.

## Refreshes keep returning 403

A single `403` followed by a `200` is normal. It's the "here's a fresh challenge, retry" round trip, and it happens
typically after a session sat idle for longer than the refresh challenge lifetime. Repeated `403`s for the same
session mean the challenge the browser signed is never
found:

- **The cache is per process** (`LocMemCache` with several workers). The challenge was issued by one worker and
  checked by another. Use a shared cache. This also bites with a *single* worker that gets restarted: gunicorn's
  sync worker is killed after 30 s when a browser holds an idle TLS connection (`WORKER TIMEOUT` in its log), and a
  per-process cache dies with it. Use threaded workers (`--threads`) or an async server.
- **The cache is evicting entries** under memory pressure. Give it more room, or use a dedicated cache.

## Users with `REQUIRE_BINDING` are logged out after ~30 s

That's mode C working as designed for users whose browsers can't bind. Check:

- that the user's browser supports DBSC (see "The browser never binds" above)
- that `BINDING_GRACE_SECONDS` isn't set too low for slow devices

## `ImproperlyConfigured` errors

| Message | Fix |
|---|---|
| `device_bound_required needs django_dbsc.middleware.DeviceBoundSessionMiddleware in MIDDLEWARE` | Add the middleware. |
| `DJANGO_DBSC['REQUIRE_BINDING'] = '…' cannot be imported` | Fix the dotted path to your policy function. |
