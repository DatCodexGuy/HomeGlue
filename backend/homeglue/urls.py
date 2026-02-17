from django.conf import settings
from django.views.static import serve
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import RedirectView
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from django.conf import settings

urlpatterns = [
    path("", RedirectView.as_view(url="/app/", permanent=False)),
    path("app/", include("apps.ui.urls")),
    path("wiki/", include(("apps.ui.public_wiki_urls", "public_wiki"), namespace="public_wiki")),
    path("share/", include(("apps.ui.public_urls", "public"), namespace="public")),
    path("accounts/", include("django.contrib.auth.urls")),
    path("admin/", admin.site.urls),
    path("api/", include("apps.api.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="api-schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="api-schema"), name="api-docs"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="api-schema"), name="api-redoc"),
]

if getattr(settings, "HOMEGLUE_OIDC_ENABLED", False):
    urlpatterns.append(path("oidc/", include("mozilla_django_oidc.urls")))

# Serve uploaded media directly from Django for now (simplifies early testing).
# NOTE: django.conf.urls.static.static() is DEBUG-gated; use an explicit route.
# For a real deployment, front this with a reverse proxy / object storage.
urlpatterns += [
    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT}),
]
