from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import dj_database_url
import environ

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    HOMEGLUE_DEBUG=(bool, False),
    HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED=(bool, False),
    HOMEGLUE_OIDC_ENABLED=(bool, False),
    HOMEGLUE_TRUST_X_FORWARDED_FOR=(bool, False),
)

DEBUG = env("HOMEGLUE_DEBUG")
SECRET_KEY = env("HOMEGLUE_SECRET_KEY", default="insecure-dev-key")

ALLOWED_HOSTS = [h.strip() for h in env("HOMEGLUE_ALLOWED_HOSTS", default="localhost,127.0.0.1").split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "apps.core.apps.CoreConfig",
    "apps.people.apps.PeopleConfig",
    "apps.assets.apps.AssetsConfig",
    "apps.docsapp.apps.DocsAppConfig",
    "apps.checklists.apps.ChecklistsConfig",
    "apps.secretsapp.apps.SecretsAppConfig",
    "apps.netapp.apps.NetAppConfig",
    "apps.flexassets.apps.FlexAssetsConfig",
    "apps.integrations.apps.IntegrationsConfig",
    "apps.audit.apps.AuditConfig",
    "apps.versionsapp.apps.VersionsAppConfig",
    "apps.workflows.apps.WorkflowsConfig",
    "apps.backups.apps.BackupsConfig",
    "apps.api",
    "apps.ui.apps.UiConfig",
]

MIDDLEWARE = [
    "apps.core.middleware.DynamicDbSettingsMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.IpAccessControlMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.ui.middleware.OrgRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.audit.middleware.AuditContextMiddleware",
]

ROOT_URLCONF = "homeglue.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.ui.context.homeglue_flags",
            ],
        },
    }
]

WSGI_APPLICATION = "homeglue.wsgi.application"

DATABASES = {
    "default": dj_database_url.parse(
        env("DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}"),
        conn_max_age=60,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

LOGIN_URL = "/accounts/login/"

STATIC_URL = "static/"
STATIC_ROOT = "/data/static"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = "/data/media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CORS_ALLOWED_ORIGINS = [o.strip() for o in env("HOMEGLUE_CORS_ALLOWED_ORIGINS", default="").split(",") if o.strip()]
CSRF_TRUSTED_ORIGINS = [o.strip() for o in env("HOMEGLUE_CSRF_TRUSTED_ORIGINS", default="").split(",") if o.strip()]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
}

HOMEGLUE_FERNET_KEY = env("HOMEGLUE_FERNET_KEY", default="")

# Base URL for links in notifications (optional).
HOMEGLUE_BASE_URL = env("HOMEGLUE_BASE_URL", default="").strip().rstrip("/")

# Email delivery (workflows notifications)
HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED = env("HOMEGLUE_EMAIL_NOTIFICATIONS_ENABLED", default=False)
HOMEGLUE_EMAIL_BACKEND = env("HOMEGLUE_EMAIL_BACKEND", default="console").strip().lower()
DEFAULT_FROM_EMAIL = env("HOMEGLUE_EMAIL_FROM", default="homeglue@localhost")

# Re-auth TTL for sensitive operations (password reveal, OTP codes, etc.)
HOMEGLUE_REAUTH_TTL_SECONDS = env.int("HOMEGLUE_REAUTH_TTL_SECONDS", default=900)

if HOMEGLUE_EMAIL_BACKEND in {"smtp", "smtp+tls", "smtp+ssl"}:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = env("HOMEGLUE_SMTP_HOST", default="")
    EMAIL_PORT = env.int("HOMEGLUE_SMTP_PORT", default=587)
    EMAIL_HOST_USER = env("HOMEGLUE_SMTP_USER", default="")
    EMAIL_HOST_PASSWORD = env("HOMEGLUE_SMTP_PASSWORD", default="")
    EMAIL_USE_TLS = HOMEGLUE_EMAIL_BACKEND in {"smtp", "smtp+tls"} and bool(env("HOMEGLUE_SMTP_USE_TLS", default=True))
    EMAIL_USE_SSL = HOMEGLUE_EMAIL_BACKEND == "smtp+ssl" or bool(env("HOMEGLUE_SMTP_USE_SSL", default=False))
else:
    # Default: print emails to the app logs (safe dev default).
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Webhook delivery (workflows notifications)
HOMEGLUE_WEBHOOK_TIMEOUT_SECONDS = env.int("HOMEGLUE_WEBHOOK_TIMEOUT_SECONDS", default=8)
HOMEGLUE_SMTP_TIMEOUT_SECONDS = env.int("HOMEGLUE_SMTP_TIMEOUT_SECONDS", default=10)

# IP access control (optional)
HOMEGLUE_IP_ALLOWLIST = env("HOMEGLUE_IP_ALLOWLIST", default="").strip()
HOMEGLUE_IP_BLOCKLIST = env("HOMEGLUE_IP_BLOCKLIST", default="").strip()
HOMEGLUE_TRUST_X_FORWARDED_FOR = env("HOMEGLUE_TRUST_X_FORWARDED_FOR", default=False)
HOMEGLUE_TRUSTED_PROXY_CIDRS = env("HOMEGLUE_TRUSTED_PROXY_CIDRS", default="").strip()

# OIDC SSO (optional; mozilla-django-oidc)
HOMEGLUE_OIDC_ENABLED = env("HOMEGLUE_OIDC_ENABLED", default=False)
if HOMEGLUE_OIDC_ENABLED:
    AUTHENTICATION_BACKENDS = (
        "apps.core.oidc.HomeGlueOIDCBackend",
        "django.contrib.auth.backends.ModelBackend",
    )
    # mozilla-django-oidc settings
    OIDC_RP_CLIENT_ID = env("HOMEGLUE_OIDC_CLIENT_ID", default="")
    OIDC_RP_CLIENT_SECRET = env("HOMEGLUE_OIDC_CLIENT_SECRET", default="")
    OIDC_OP_AUTHORIZATION_ENDPOINT = env("HOMEGLUE_OIDC_AUTHORIZATION_ENDPOINT", default="")
    OIDC_OP_TOKEN_ENDPOINT = env("HOMEGLUE_OIDC_TOKEN_ENDPOINT", default="")
    OIDC_OP_USER_ENDPOINT = env("HOMEGLUE_OIDC_USER_ENDPOINT", default="")
    OIDC_OP_JWKS_ENDPOINT = env("HOMEGLUE_OIDC_JWKS_ENDPOINT", default="")
    OIDC_RP_SIGN_ALGO = env("HOMEGLUE_OIDC_SIGN_ALGO", default="RS256")
    OIDC_RP_SCOPES = env("HOMEGLUE_OIDC_SCOPES", default="openid email profile").split()
    # Prefer redirecting users into SSO rather than local login when enabled.
    LOGIN_URL = "/oidc/authenticate/"

SPECTACULAR_SETTINGS = {
    "TITLE": "HomeGlue API",
    "DESCRIPTION": "HomeGlue API (org-scoped). Most endpoints require explicit org context.",
    "VERSION": "0.1",
    # Lock down docs endpoints; this app is org-scoped and not meant to be anonymous.
    "SERVE_PERMISSIONS": ["rest_framework.permissions.IsAuthenticated"],
}
