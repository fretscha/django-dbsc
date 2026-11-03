import time

from django_dbsc.services.cookie import BoundCookieCodec


def test_encoded_cookie_is_valid_for_its_session():
    codec = BoundCookieCodec(max_age=600)

    assert codec.is_valid(codec.encode("s1"), "s1")


def test_cookie_for_another_dbsc_session_is_rejected():
    codec = BoundCookieCodec(max_age=600)

    assert not codec.is_valid(codec.encode("s1"), "s2")


def test_expired_cookie_is_rejected():
    issued_long_ago = BoundCookieCodec(max_age=600, clock=lambda: time.time() - 601)

    assert not BoundCookieCodec(max_age=600).is_valid(issued_long_ago.encode("s1"), "s1")


def test_tampered_cookie_is_rejected():
    codec = BoundCookieCodec(max_age=600)
    value = codec.encode("s1")

    assert not codec.is_valid(value[:-1] + ("A" if value[-1] != "A" else "B"), "s1")


def test_missing_or_garbage_cookie_is_rejected():
    codec = BoundCookieCodec(max_age=600)

    assert not codec.is_valid(None, "s1")
    assert not codec.is_valid("", "s1")
    assert not codec.is_valid("garbage", "s1")
