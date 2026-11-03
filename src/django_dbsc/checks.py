from django.core import checks

from django_dbsc import conf

# WHY 300: Chrome refreshes proactively once <2 min of the bound cookie remain, and allows only ~2 signings per
# 3-5 min. Shorter lifetimes make it skip refreshes (Secure-Session-Skipped: quota_exceeded). See
# docs/real-browser-testing.md.
MIN_BOUND_COOKIE_MAX_AGE = 300


def check_bound_cookie_max_age(app_configs, **kwargs):
    max_age = conf.get("BOUND_COOKIE_MAX_AGE")
    if max_age < MIN_BOUND_COOKIE_MAX_AGE:
        return [
            checks.Warning(
                f"DJANGO_DBSC['BOUND_COOKIE_MAX_AGE'] is {max_age}s, below {MIN_BOUND_COOKIE_MAX_AGE}s.",
                hint="Chrome will exhaust its signing quota and skip refreshes, which ends legitimate sessions. "
                "Use 300 or more (default 600).",
                id="django_dbsc.W001",
            )
        ]
    return []
