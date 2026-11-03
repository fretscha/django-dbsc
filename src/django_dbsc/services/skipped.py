"""Parsing of ``Secure-Session-Skipped``, which a browser sends when it chose not to refresh (spec §headers).

The header is client-controlled. It must never grant access; it may only soften how a rejection is handled.
"""

import secrets

import http_sf


def names_session(header_value: str | None, session_identifier: str) -> bool:
    """True if the header reports a skipped refresh for exactly this DBSC session."""
    if not header_value:
        return False
    try:
        entries = http_sf.parse(header_value.encode(), tltype="list")
    except (http_sf.StructuredFieldError, UnicodeEncodeError):
        return False
    if not isinstance(entries, list):
        return False
    expected = session_identifier.encode()
    for entry in entries:
        # Each list member is (value, params). Check the shape explicitly: this is attacker-controlled input.
        if not (isinstance(entry, tuple) and len(entry) == 2 and isinstance(entry[1], dict)):
            continue
        candidate = entry[1].get("session_identifier")
        # WHY type(...) is str: the spec defines an sf-string, and http_sf's Token subclasses str.
        if type(candidate) is str and secrets.compare_digest(candidate.encode(), expected):
            return True
    return False
