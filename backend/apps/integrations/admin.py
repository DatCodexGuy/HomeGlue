from __future__ import annotations

from django.contrib import admin

from .models import ProxmoxConnection, ProxmoxGuest, ProxmoxNetwork, ProxmoxNode


@admin.register(ProxmoxConnection)
class ProxmoxConnectionAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "base_url", "enabled", "verify_ssl", "last_sync_at", "last_sync_ok")
    list_filter = ("enabled", "verify_ssl", "last_sync_ok")
    search_fields = ("name", "base_url", "token_id")


@admin.register(ProxmoxNode)
class ProxmoxNodeAdmin(admin.ModelAdmin):
    list_display = ("connection", "node", "status", "maxcpu", "maxmem", "maxdisk", "uptime", "updated_at")
    search_fields = ("node",)


@admin.register(ProxmoxGuest)
class ProxmoxGuestAdmin(admin.ModelAdmin):
    list_display = ("connection", "guest_type", "vmid", "name", "node", "status", "maxcpu", "maxmem", "maxdisk", "updated_at")
    list_filter = ("guest_type", "status")
    search_fields = ("name", "vmid", "node")


@admin.register(ProxmoxNetwork)
class ProxmoxNetworkAdmin(admin.ModelAdmin):
    list_display = ("connection", "node", "iface", "kind", "address", "netmask", "gateway", "updated_at")
    search_fields = ("node", "iface", "address")

