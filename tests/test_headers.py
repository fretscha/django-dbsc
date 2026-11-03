import pytest

from django_dbsc.services.headers import registration_header
from tests.support import parse_registration


def test_registration_header_advertises_es256_first_then_rs256():
    header = registration_header(path="/dbsc/register", challenge="c1")

    ((algs, _),) = parse_registration(header)
    assert algs == ["ES256", "RS256"]


def test_registration_header_carries_path_and_challenge():
    header = registration_header(path="/dbsc/register", challenge="c1")

    assert header == '(ES256 RS256);path="/dbsc/register";challenge="c1"'


def test_registration_header_includes_authorization_only_when_given():
    ((_, with_auth),) = parse_registration(registration_header(path="/r", challenge="c1", authorization="code-123"))
    ((_, without_auth),) = parse_registration(registration_header(path="/r", challenge="c1"))

    assert with_auth["authorization"] == "code-123"
    assert "authorization" not in without_auth


def test_registration_header_quotes_values_safely():
    # sf-string escaping: a quote in the value must not break out of the parameter.
    header = registration_header(path='/r";path="/evil', challenge="c1")

    ((_, params),) = parse_registration(header)
    assert params["path"] == '/r";path="/evil'


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_registration_header_refuses_algs_we_will_not_verify(alg):
    with pytest.raises(ValueError, match="alg"):
        registration_header(path="/r", challenge="c1", algs=(alg,))
