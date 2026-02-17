from __future__ import annotations

from django.urls import path

from . import views

app_name = "public_wiki"

urlpatterns = [
    path("", views.public_wiki_index, name="wiki_index"),
    path("<slug:slug>/", views.public_wiki_page, name="wiki_page"),
]

