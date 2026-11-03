# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-11-03

First usable release. It implements the server side of the
[W3C DBSC draft](https://w3c.github.io/webappsec-dbsc/), verified end to end in Chrome 156.

### Added

- Supported: Python 3.12–3.14, Django 5.2, 6.0 and 6.1 (all combinations tested in CI)

- `DeviceBoundSessionMiddleware`:
  - offers registration after every `login()`
  - enforces the short-lived bound cookie on bound sessions
  - sets `request.dbsc_bound`
- Registration and refresh endpoints (`django_dbsc.urls`):
  - ES256/RS256 proof verification
  - single-use challenges scoped to one session
  - spec status semantics: `403` means retry with the new challenge, `401` ends the session, `503` on backend errors
- `@device_bound_required` decorator, with an optional `STEP_UP_URL` redirect
- `REQUIRE_BINDING` policies (`staff_only`, `superusers_only`, `everyone`, or your own callable), with a grace period
- Revocation on logout, on rejected requests and on re-registration, with an audit reason (`revoked_reason`)
- `Secure-Session-Skipped` support: a refresh the browser skipped for this session is refused, but the session is kept
- Refresh challenges whose lifetime fits the browser's refresh cadence (`REFRESH_CHALLENGE_TTL`)
- System check `django_dbsc.W001` for bound-cookie lifetimes below 300 s
- Documentation: user guide, configuration reference, security model, troubleshooting
- `example/` demo project, and a real-browser test harness for Chrome

### Known limitations

- No built-in rate limiting on the DBSC endpoints. The work per request is bounded (see the security model). An
  optional per-session limit at the reverse proxy is described in the deployment checklist.
- The first refresh after registration takes one extra `403` round trip in Chrome.
- Site-scoped sessions (`include_site`) and federated sessions are not supported.

[Unreleased]: https://github.com/fretscha/django-dbsc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fretscha/django-dbsc/releases/tag/v0.1.0
