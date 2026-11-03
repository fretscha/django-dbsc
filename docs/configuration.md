# Configuration

All settings live in one dict in `settings.py`. Every key is optional.

```python
DJANGO_DBSC = {
    "EXEMPT_PATH_PREFIXES": ["/dbsc/", "/static/"],
    "BOUND_COOKIE_MAX_AGE": 600,
    "REGISTRATION_PATH": "/dbsc/register",
    "REFRESH_URL": "/dbsc/refresh",
    "REFRESH_CHALLENGE_TTL": None,
    "STEP_UP_URL": None,
    "REQUIRE_BINDING": None,
    "BINDING_GRACE_SECONDS": 30,
}
```

## Settings

### `EXEMPT_PATH_PREFIXES`

**Default:** `["/dbsc/"]`

URL path prefixes where a bound session is **not** required to present its bound cookie, and where `REQUIRE_BINDING`
is not enforced. They are also sent to the browser as scope `exclude` rules, so the browser never holds back a
request to these paths while it refreshes.

- **Always** keep the prefix of the DBSC endpoints. The browser calls `/dbsc/refresh` precisely *because* its bound
  cookie has expired.
- Add your `STATIC_URL` and `MEDIA_URL`. Assets don't need protection, and you don't want them delayed by a refresh.
- Matching is by plain prefix: `"/static/"` covers `/static/app.css`.

```python
"EXEMPT_PATH_PREFIXES": ["/dbsc/", "/static/", "/media/"],
```

### `BOUND_COOKIE_MAX_AGE`

**Default:** `600` (seconds) · **Minimum recommended:** `300`

Lifetime of the short-lived `dbsc_bound` cookie that proves device possession. When it nears expiry, the browser signs
a new challenge to get a fresh one.

- **Shorter** means a stolen bound cookie is useful for less time, and revocations take effect sooner. The cost is
  more refreshes.
- **Below 300 s it breaks.** Chrome refreshes once less than 2 minutes remain and allows only about 2 signatures per
  3–5 minutes. When it's over that quota it skips refreshes, and those users get `401`s until the quota recovers.
  `manage.py check` warns about this as `django_dbsc.W001`.

### `REGISTRATION_PATH`

**Default:** `"/dbsc/register"`

The path the browser POSTs its registration to. It must match where you mounted `django_dbsc.urls`. If you use
`path("auth/dbsc/", include("django_dbsc.urls"))`, set it to `"/auth/dbsc/register"`.

### `REFRESH_URL`

**Default:** `"/dbsc/refresh"`

The path the browser POSTs refreshes to. It must match your URL mount, like `REGISTRATION_PATH`. It must be on the
same site as your pages, and it must be HTTPS.

### `REFRESH_CHALLENGE_TTL`

**Default:** `None`, which means `BOUND_COOKIE_MAX_AGE + 60`

How long a refresh challenge stays valid. The browser receives a challenge with each successful refresh and signs it
at the *next* refresh, roughly `BOUND_COOKIE_MAX_AGE - 120` seconds later. If challenges expire before that, every
refresh needs an extra round trip (a `403` with a new challenge, then a retry). You rarely need to change this.

Challenges are single-use and bound to one session, and using one needs the device's private key. Registration
challenges always expire after 120 seconds.

### `STEP_UP_URL`

**Default:** `None`

Where `@device_bound_required` sends requests from unbound sessions, typically a re-authentication or MFA page.
The original URL is passed as `?next=`. With `None`, those requests get `403 Forbidden`.

```python
"STEP_UP_URL": "/accounts/reauth/",
```

### `REQUIRE_BINDING`

**Default:** `None` (no requirement)

Selects users whose sessions **must** become bound (mode C in the [guide](guide.md#c-required-binding)). Accepts a
callable `(user) -> bool`, or its dotted path. Built-in: `"django_dbsc.policies.staff_only"`,
`"django_dbsc.policies.superusers_only"`, `"django_dbsc.policies.everyone"`.

When unset, user objects are not inspected at all, so there is no extra cost.

### `BINDING_GRACE_SECONDS`

**Default:** `30`

How long a session that `REQUIRE_BINDING` selects may stay unbound before it is ended. The clock starts at the first
request the middleware sees for that user, not at login. That gives sessions that existed before you enabled the
policy a fair start.

Registration usually finishes in under a second. The margin covers slow devices and networks.

## Other names you may need

| Name | Value | Notes |
|---|---|---|
| Bound cookie | `dbsc_bound` | `Path=/; Secure; HttpOnly; SameSite=Lax` |
| URL names | `django_dbsc:register`, `django_dbsc:refresh` | from `include("django_dbsc.urls")` |
| Logger | `django_dbsc` | see [Logging](guide.md#logging) |
| System check | `django_dbsc.W001` | `BOUND_COOKIE_MAX_AGE` below 300 s |
| Request attribute | `request.dbsc_bound` | set by the middleware |
| Model | `django_dbsc.DeviceBoundSession` | one row per binding, never deleted |

## Requirements outside `DJANGO_DBSC`

- **`CACHES["default"]`** must be shared by all processes (Redis, Memcached, database cache). It stores the
  challenges.
- **Sessions:** any Django session backend works.
- **Middleware order:** after `SessionMiddleware` and `AuthenticationMiddleware`.
