from django.core import checks

from django_dbsc.checks import check_bound_cookie_max_age


def _ids(settings_dbsc, settings):
    settings.DJANGO_DBSC = {**settings.DJANGO_DBSC, **settings_dbsc}
    return [m.id for m in check_bound_cookie_max_age(app_configs=None)]


def test_default_lifetime_passes(settings):
    assert _ids({}, settings) == []


def test_lifetime_below_chrome_quota_floor_warns(settings):
    # Real-browser finding: Chrome refreshes proactively in the last 2 min and allows ~2 signings per 3-5 min.
    assert _ids({"BOUND_COOKIE_MAX_AGE": 20}, settings) == ["django_dbsc.W001"]


def test_floor_itself_passes(settings):
    assert _ids({"BOUND_COOKIE_MAX_AGE": 300}, settings) == []


def test_check_is_registered_with_django():
    assert check_bound_cookie_max_age in checks.registry.registry.get_checks()
