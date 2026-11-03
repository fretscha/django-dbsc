from django.apps import AppConfig


class DjangoDbscConfig(AppConfig):
    name = "django_dbsc"
    verbose_name = "Device Bound Sessions"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from django.contrib.auth.signals import user_logged_in

        from django_dbsc.services.registration import request_registration_offer

        user_logged_in.connect(request_registration_offer, dispatch_uid="django_dbsc.request_registration_offer")
