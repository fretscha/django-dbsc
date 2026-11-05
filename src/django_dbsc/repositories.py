import secrets

from django.utils import timezone

from django_dbsc.models import DeviceBoundSession

# JWK members that only appear in private keys (RFC 7518 §6.2.2, §6.3.2, §6.4.1).
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class DeviceBoundSessionRepository:
    def create(self, *, user, public_jwk: dict, alg: str) -> DeviceBoundSession:
        if alg not in DeviceBoundSession.Alg.values:
            raise ValueError(f"unsupported alg {alg!r}")
        if PRIVATE_JWK_MEMBERS & public_jwk.keys():
            # WHY: an exported private key isn't device-bound. Refuse it rather than store a secret.
            raise ValueError("jwk contains private key material")
        return DeviceBoundSession.objects.create(
            session_identifier=secrets.token_urlsafe(32), user=user, public_jwk=public_jwk, alg=alg
        )

    def get_active(self, session_identifier: str) -> DeviceBoundSession | None:
        return (
            DeviceBoundSession.objects.select_related("user")
            .filter(session_identifier=session_identifier, revoked_at__isnull=True)
            .first()
        )

    def mark_refreshed(self, session: DeviceBoundSession) -> None:
        session.last_refreshed_at = timezone.now()
        DeviceBoundSession.objects.filter(pk=session.pk).update(last_refreshed_at=session.last_refreshed_at)

    def revoke(self, session_identifier: str, reason: str = "") -> bool:
        return self._revoke(reason, session_identifier=session_identifier) > 0

    async def arevoke(self, session_identifier: str, reason: str = "") -> bool:
        updated = await DeviceBoundSession.objects.filter(
            revoked_at__isnull=True, session_identifier=session_identifier
        ).aupdate(revoked_at=timezone.now(), revoked_reason=reason)
        return updated > 0

    def revoke_all_for_user(self, user, reason: str = "") -> int:
        return self._revoke(reason, user=user)

    def _revoke(self, reason: str, **filters) -> int:
        # WHY a single UPDATE: it's atomic, and the revoked_at filter makes repeat calls report 0 and keeps the
        # first reason intact.
        return DeviceBoundSession.objects.filter(revoked_at__isnull=True, **filters).update(
            revoked_at=timezone.now(), revoked_reason=reason
        )
