# How it works & security model

## The threat it addresses

Malware and infostealers copy session cookies off a user's machine and replay them elsewhere. Passwords and MFA don't
help, because the attacker skips the login entirely. DBSC makes the session usable only by the device that holds a
private key, and the browser keeps that key in non-exportable hardware.

## The moving parts

```
                    ┌───────────────────────── your Django app ─────────────────────────┐
Browser             │ DeviceBoundSessionMiddleware        /dbsc/register  /dbsc/refresh │
(device key in      │  • offers registration after login  • verify proof  • verify proof│
 TPM/Secure Enclave)│  • enforces the bound cookie        • store pub key • new cookie  │
                    │  • sets request.dbsc_bound          • set cookie    • next challenge
                    └────────────────────────────────────────────────────────────────────┘
```

Two cookies work together:

| Cookie | Lifetime | Proves |
|---|---|---|
| `sessionid` (Django) | long (your `SESSION_COOKIE_AGE`) | who the user is |
| `dbsc_bound` | short (`BOUND_COOKIE_MAX_AGE`, default 10 min) | that the device key was used recently |

The `dbsc_bound` cookie is signed with your `SECRET_KEY` and names the binding it belongs to. Only someone who can sign
a fresh challenge with the device key can obtain a new one.

## What the server checks

**Registration** (`POST /dbsc/register`):

- The user is logged in, and the request is not cross-site.
- The proof is a JWT with `typ: dbsc+jwt`, signed with `ES256` or `RS256`. `alg: none` is always refused.
- The signature is valid for the public key embedded in the proof.
- The proof answers a challenge that was issued to **this** login session in the last 120 seconds, and the challenge
  is single-use.
- The public key contains no private key material.

**Every request on a bound session:**

- The `dbsc_bound` cookie is present, unexpired, correctly signed, and names this session's binding.
  This check is stateless: no DB query.

**Refresh** (`POST /dbsc/refresh`):

- `Sec-Secure-Session-Id` names the binding stored in the current Django session.
- The binding is not revoked, and belongs to the logged-in user.
- The proof carries **no** embedded key. It's verified against the stored key, with the algorithm from registration.
- It answers an unexpired, unused challenge for this binding.

## How the server responds

The browser acts on status codes, so they are chosen deliberately:

| Situation | Response | Browser does |
|---|---|---|
| Valid refresh | `200` + new cookie + next challenge | continues |
| Missing or expired challenge | `403` + fresh challenge | signs it and retries once |
| Wrong key, revoked, logged out, wrong user | `401` | ends its DBSC session |
| Database error | `503` | backs off and keeps the session |
| Bound session without valid cookie | `401`, session ended, binding revoked | — |
| …and the browser reports a skipped refresh for this session | `401`, session **kept** | recovers on its next refresh |

## What is protected, and what isn't

| Scenario | Protected? |
|---|---|
| Attacker replays a stolen `sessionid` from another machine | ✅ `401`; the session is ended and the binding revoked |
| Attacker forges `Secure-Session-Skipped` to avoid that | ✅ still `401`; the header can soften the response but never grants access |
| Attacker replays a stolen `dbsc_bound` cookie into a different session | ✅ the cookie names its binding |
| Attacker uses a browser without DBSC to "downgrade" a bound session | ✅ the server remembers the binding |
| Attacker steals `sessionid` **and** a fresh `dbsc_bound` together | ⚠️ works until that cookie expires (≤ `BOUND_COOKIE_MAX_AGE`), then refresh is impossible without the key |
| Malware running on the victim's device, using the browser itself | ❌ out of scope: the key is used through the legitimate browser |
| Sessions in browsers without DBSC (Firefox, Safari today) | ❌ unprotected, unless `REQUIRE_BINDING` keeps those users out |
| Theft in the first moments after login, before registration completes | ⚠️ brief window; see below |

**The registration window.** Between the login response and the browser's background registration (usually
milliseconds), the session isn't bound yet. An attacker who steals `sessionid` in exactly that window could try to
register their own key first. Challenges are single-use, so only one side can win. If the attacker wins, the real
browser's next request has no valid bound cookie, and the session is ended for both. It fails safe, but the user
must log in again.

**Forced logout.** Anyone holding a stolen `sessionid` can make the server end that session, by sending a request
without the bound cookie. That's deliberate: the stolen session dies too, so the attacker gains no access, but the
victim has to log in again.

## Deliberate design choices

- **The `Secure-Session-Skipped` header can soften a rejection but never grants access.** Real browsers send it when
  they choose not to refresh (signing quota, unreachable endpoint). It names a session, but any client can forge it.
  When it names *this* session, the request is still refused, but the session isn't ended. When it's missing,
  malformed or names another session, the strict path applies.
- **The DBSC endpoints don't use CSRF tokens.** The browser makes these requests itself. The signed proof is the
  anti-forgery check, and cross-site requests are refused.
- **Revocation is a soft delete.** Bindings are kept with a reason, for auditing.
- **Fail closed.** `@device_bound_required` refuses to run without the middleware. An invalid `REQUIRE_BINDING`
  fails at startup.
- **Fail open only where it's safe.** Database errors during refresh return `503`, not a `4xx` that would end the
  user's session. Database errors during revocation still return `401`.
