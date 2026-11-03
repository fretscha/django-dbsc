from typing import ClassVar

from django.conf import settings
from django.db import models


class DeviceBoundSession(models.Model):
    """A DBSC session: one device key bound to one Django login."""

    class Alg(models.TextChoices):
        ES256 = "ES256"
        RS256 = "RS256"

    session_identifier = models.CharField(max_length=64, unique=True, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="device_bound_sessions")
    public_jwk = models.JSONField()
    alg = models.CharField(max_length=8, choices=Alg.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    last_refreshed_at = models.DateTimeField(null=True, blank=True)
    # WHY soft revoke: keeps an audit trail of which device keys were cut off and when.
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Short machine-readable cause, e.g. "logout" or "missing_bound_cookie". The first cause wins.
    revoked_reason = models.CharField(max_length=64, blank=True, default="")

    # WHY explicit: type checkers without a Django plugin (ty) can't see the implicit default manager.
    objects: ClassVar[models.Manager] = models.Manager()

    class Meta:
        indexes = [models.Index(fields=["user", "revoked_at"])]

    def __str__(self) -> str:
        return f"{self.user} [{self.alg}] {self.session_identifier:.8}…"
