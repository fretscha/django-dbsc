# Security policy

django-dbsc is a security library, so reports about it are especially welcome.

## Reporting a vulnerability

**Please don't open a public issue for a security problem.** Report it privately instead:

1. Go to [Report a vulnerability](https://github.com/fretscha/django-dbsc/security/advisories/new)
   (the repository's **Security** tab → **Report a vulnerability**).
2. Describe what an attacker can do, and how to reproduce it. A failing test or a short script helps most.

The report is visible only to you and the maintainer.

## What to expect

django-dbsc has a single maintainer, so everything here is best effort:

- an acknowledgement of your report, normally within a week
- a fix or a mitigation in a new release, with you credited in the changelog and the advisory if you want that
- a published GitHub security advisory once a fixed release is on PyPI

## Supported versions

The project is in alpha. Only the latest release on [PyPI](https://pypi.org/project/django-dbsc/) receives security
fixes. Fixes are not backported to older `0.x` releases.

## Scope

The [security model](https://github.com/fretscha/django-dbsc/blob/main/docs/security.md) lists what django-dbsc
protects against and what it deliberately doesn't. A report is in scope if it breaks one of the protections listed
there, for example:

- using a bound session without holding the device key
- registering or refreshing a binding without a valid proof
- getting access through a forged `Secure-Session-Skipped` header
- bypassing `@device_bound_required` or a `REQUIRE_BINDING` policy

The limitations that page already documents (malware driving the victim's own browser, sessions in browsers without
DBSC, the short registration window after login) are known and are not vulnerabilities. Ideas for narrowing them are
welcome as regular issues.

Problems in the DBSC protocol itself belong with the [W3C spec](https://github.com/w3c/webappsec-dbsc), and problems
in a browser's implementation belong with that browser's vendor.
