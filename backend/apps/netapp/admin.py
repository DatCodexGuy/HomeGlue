from __future__ import annotations

from django.contrib import admin

from .models import Domain, SSLCertificate


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "status", "expires_on", "auto_renew", "registrar", "dns_provider", "updated_at")
    list_filter = ("status", "auto_renew")
    search_fields = ("name", "registrar", "dns_provider")


@admin.register(SSLCertificate)
class SSLCertificateAdmin(admin.ModelAdmin):
    list_display = ("common_name", "organization", "issuer", "not_after", "fingerprint_sha256", "updated_at")
    search_fields = ("common_name", "issuer", "serial_number", "fingerprint_sha256")
    list_filter = ("issuer",)

