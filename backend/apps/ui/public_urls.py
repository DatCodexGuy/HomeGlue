from __future__ import annotations

from django.urls import path

from . import public_views

app_name = "public"

urlpatterns = [
    path("p/<str:token>/", public_views.password_share, name="password_share"),
]

