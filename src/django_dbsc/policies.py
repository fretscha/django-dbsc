"""Built-in REQUIRE_BINDING rules. Any ``callable(user) -> bool`` works; these cover the common cases."""


def staff_only(user) -> bool:
    return bool(user.is_staff)


def superusers_only(user) -> bool:
    return bool(user.is_superuser)


def everyone(user) -> bool:
    # This locks out every browser without DBSC support. Only use it when all clients are known to support it.
    return True
