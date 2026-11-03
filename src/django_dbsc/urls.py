from django.urls import path

from django_dbsc.api import views

app_name = "django_dbsc"

urlpatterns = [
    path("register", views.register_view, name="register"),
    path("refresh", views.refresh_view, name="refresh"),
]
