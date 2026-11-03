# django-dbsc

> **Status: planning / pre-alpha.** Not usable yet. Do not install it in production.

Django support for [Device Bound Session Credentials (DBSC)](https://w3c.github.io/webappsec-dbsc/).
It binds a Django session to a non-exportable device key, so a stolen session cookie on its own is no longer
enough to hijack the session.

Planned components:

- A registration hook that emits `Secure-Session-Registration` after login
- `register` and `refresh` endpoints that verify the DBSC proof JWT (ES256 / RS256)
- A middleware that enforces a short-lived bound cookie for bound sessions
