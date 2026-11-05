# WHY in session data, not keyed on session_key: cycle_key() rotates the key and would silently unbind the session.
SESSION_DBSC_ID = "_dbsc_id"
BOUND_COOKIE_NAME = "dbsc_bound"

REGISTRATION_HEADER = "Secure-Session-Registration"
RESPONSE_HEADER = "Secure-Session-Response"
CHALLENGE_HEADER = "Secure-Session-Challenge"
SESSION_ID_HEADER = "Sec-Secure-Session-Id"
SKIPPED_HEADER = "Secure-Session-Skipped"
SESSION_BINDING_REQUIRED_SINCE = "_dbsc_required_since"
# Set at registration. The first bound response then carries a refresh challenge that Chrome will cache.
SESSION_CHALLENGE_PENDING = "_dbsc_challenge_pending"
