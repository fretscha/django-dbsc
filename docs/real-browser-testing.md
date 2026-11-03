# Real-browser testing (Chrome)

Tested on 2026-11-03 with Chrome 156.0.8078.80 on macOS (Apple M2 Max), against `example/` served over HTTPS on
localhost.

## Results

| Behaviour | Result |
|---|---|
| `Secure-Session-Registration` on the **302** after `LoginView` POST | ✅ Honoured. Chrome registered ~10 ms after the redirect. |
| First page after login | Unbound, as expected: registration runs in the background |
| Registration proof (ES256 JWT) verified by `verify_registration_proof` | ✅ |
| Bound cookie attributes match the declared `credentials` | ✅ No refresh loop |
| `@device_bound_required` after registration | ✅ 200 (403 before) |
| Path-prefix exclude (`{"type": "exclude", "path": "/static/"}`) | ✅ No refresh triggered for `/static/app.css` with an expired cookie |
| Expired cookie → blocking refresh → **403 + new challenge → retry → 200** → original request | ✅ Whole round trip in < 10 ms |
| Replaying only a stolen `sessionid` (no bound cookie) | ✅ 401, and the session is flushed |
| Refresh answered with **401** | ✅ Chrome drops its DBSC session and stops sending `Secure-Session-Skipped` |
| Logout | ✅ Binding revoked, `dbsc_bound` cleared |
| `Sec-Fetch-*` on DBSC fetches (register and refresh) | `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: no-cors`, `Sec-Fetch-Dest: empty` |

## Findings that change the library

1. **Chrome needs HTTPS, even on localhost.** Over `http://localhost` Chrome ignored the registration header
   completely: no request and no DevTools event, for any header variant. The spec allows localhost; Chrome 156
   does not. Local development needs TLS (see setup below).
2. **The bound-cookie lifetime has a floor.** Chrome refreshes *proactively* when the bound cookie has less than
   2 minutes left, and allows only about 2 signings per 3–5 minutes (`SigningQuotaExceeded`). With a 20-second
   cookie, Chrome skipped refreshes and sent `Secure-Session-Skipped: quota_exceeded`. The middleware then
   logged out a legitimate user. Keep `BOUND_COOKIE_MAX_AGE` ≥ 300 s (the default 600 s produced no proactive
   refreshes at all). → Add a Django system check.
3. **`Secure-Session-Skipped` from a real browser causes logouts.** It is still forgeable, so it must never
   grant access. But it could *soften* the consequence: answer 401 *without* flushing the session when the
   header is present, and flush only when it's absent. A thief gains nothing either way (still 401, no key), and
   a legitimate browser over its signing quota recovers on the next successful refresh.
4. **A middleware rejection leaves the binding active, and Chrome's DBSC session alive.** The flushed session's
   `DeviceBoundSession` row stays unrevoked. Chrome keeps the session until a refresh is answered with 401.
   → Revoke on rejection, and record a reason.
5. **One refresh used a challenge the server no longer knew** and needed the 403 retry. It recovered
   transparently, but the cause (stale cached challenge vs. ordering of the two proactive refreshes) isn't
   understood yet.
6. With the `enable-standard-device-bound-session-credentials-audience` flag, Chrome adds an `aud` claim. We
   ignore `aud` today, which is fine, but checking it against our origin would be a cheap hardening step.

## Setup

DBSC on macOS is rolled out via Finch and may be off. When it's off, Chrome **silently** ignores the header.
Use an isolated profile with the features forced on. This never touches your normal Chrome.

```bash
SP=$(mktemp -d)

# 1. Throwaway TLS cert for localhost, trusted only by this Chrome instance via its SPKI hash.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $SP/key.pem -out $SP/cert.pem \
  -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
SPKI=$(openssl x509 -in $SP/cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64)

# 2. Demo server over HTTPS.
cd example && uv run python manage.py migrate && \
  DJANGO_SUPERUSER_PASSWORD=demo-pw uv run python manage.py createsuperuser --noinput --username alice --email a@x.y
uv run --with gunicorn gunicorn demo.wsgi --bind 127.0.0.1:8443 --certfile $SP/cert.pem --keyfile $SP/key.pem

# 3. Isolated Chrome with DBSC forced on and DevTools on port 9333.
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=$SP/profile --remote-debugging-port=9333 --no-first-run \
  --enable-features=DeviceBoundSessions,UseUnexportableKeyServiceInBrowserProcess,PersistDeviceBoundSessions \
  --ignore-certificate-errors-spki-list=$SPKI about:blank

# 4. Drive it (from the repo root).
uv run --with playwright python example/scripts/drive_chrome.py login    # then: refresh | steal | logout
uv run --with playwright python example/scripts/trace_dbsc_events.py /protected/
```

`example/demo/probe.py` logs every request with its `Sec-Fetch-*`, `Sec-Secure-Session-Id` and
`Secure-Session-Skipped` headers, plus the DBSC headers we sent back.

### Debugging tips

- **Chrome never POSTs to the registration path.** Check the scheme first (HTTPS), then
  `chrome://version/?show-variations-cmd` for the enabled features.
  `example/scripts/trace_dbsc_events.py` prints Chrome's own reason codes (`Network.deviceBoundSessionEventOccurred`).
- **`SigningQuotaExceeded`.** Wait about 5 minutes. To remove stale browser-side sessions, call the DevTools
  method `Network.deleteDeviceBoundSession`.
- `chrome://flags` also has `enable-bound-session-credentials-software-keys-for-manual-testing` (mock keys, no
  Secure Enclave). It wasn't needed here: the Secure Enclave path worked once HTTPS was in place.
