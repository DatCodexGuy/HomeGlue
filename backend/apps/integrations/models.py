from __future__ import annotations

from django.db import models

from apps.core.models import Organization
from apps.secretsapp.crypto import decrypt_str, encrypt_str
from apps.assets.models import Asset, ConfigurationItem


class ProxmoxConnection(models.Model):
    """
    Proxmox connection details (org-scoped).

    Uses Proxmox API tokens:
      token_id: user@realm!tokenname
      token_secret: token secret value (stored encrypted)
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="proxmox_connections")
    name = models.CharField(max_length=200, default="Proxmox")
    base_url = models.URLField(help_text="e.g. https://pve.example.com:8006")
    token_id = models.CharField(max_length=200, help_text="e.g. root@pam!homeglue")
    token_secret_ciphertext = models.TextField(blank=True, default="")
    verify_ssl = models.BooleanField(default=False, help_text="Disable for self-signed certs (not recommended).")
    enabled = models.BooleanField(default=True)
    sync_interval_minutes = models.IntegerField(default=0, help_text="0 = manual only. Suggested: 15.")

    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_sync_ok = models.BooleanField(default=False)
    last_sync_error = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["organization", "enabled", "updated_at"])]

    def set_token_secret(self, plaintext: str) -> None:
        self.token_secret_ciphertext = encrypt_str(plaintext or "")

    def get_token_secret(self) -> str:
        return decrypt_str(self.token_secret_ciphertext)

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class ProxmoxNode(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="nodes")
    asset = models.OneToOneField(Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="proxmox_node")
    config_item = models.OneToOneField(
        ConfigurationItem,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="proxmox_node",
    )
    node = models.CharField(max_length=200)
    status = models.CharField(max_length=32, blank=True, default="")
    cpu = models.FloatField(null=True, blank=True)
    maxcpu = models.IntegerField(null=True, blank=True)
    mem = models.BigIntegerField(null=True, blank=True)
    maxmem = models.BigIntegerField(null=True, blank=True)
    disk = models.BigIntegerField(null=True, blank=True)
    maxdisk = models.BigIntegerField(null=True, blank=True)
    uptime = models.BigIntegerField(null=True, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    status_raw = models.JSONField(default=dict, blank=True)
    version_raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "node")]
        indexes = [models.Index(fields=["connection", "node"])]

    def __str__(self) -> str:
        return f"{self.connection}: node {self.node}"


class ProxmoxGuest(models.Model):
    TYPE_QEMU = "qemu"
    TYPE_LXC = "lxc"
    TYPE_CHOICES = [(TYPE_QEMU, "VM"), (TYPE_LXC, "Container")]

    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="guests")
    asset = models.OneToOneField(Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="proxmox_guest")
    config_item = models.OneToOneField(ConfigurationItem, on_delete=models.SET_NULL, null=True, blank=True, related_name="proxmox_guest")
    node = models.CharField(max_length=200, blank=True, default="")
    vmid = models.IntegerField()
    guest_type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    name = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=32, blank=True, default="")
    cpu = models.FloatField(null=True, blank=True)
    maxcpu = models.IntegerField(null=True, blank=True)
    mem = models.BigIntegerField(null=True, blank=True)
    maxmem = models.BigIntegerField(null=True, blank=True)
    disk = models.BigIntegerField(null=True, blank=True)
    maxdisk = models.BigIntegerField(null=True, blank=True)
    uptime = models.BigIntegerField(null=True, blank=True)
    ip_addrs = models.JSONField(default=list, blank=True)  # best-effort parsed
    proxmox_tags = models.JSONField(default=list, blank=True)
    ostype = models.CharField(max_length=64, blank=True, default="")
    pool = models.CharField(max_length=200, blank=True, default="")
    agent_hostname = models.CharField(max_length=255, blank=True, default="")
    agent_osinfo = models.JSONField(default=dict, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    config_raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "guest_type", "vmid")]
        indexes = [
            models.Index(fields=["connection", "node"]),
            models.Index(fields=["connection", "guest_type", "vmid"]),
            models.Index(fields=["connection", "name"]),
        ]

    def __str__(self) -> str:
        label = self.name or f"{self.guest_type}:{self.vmid}"
        return f"{self.connection}: {label}"


class ProxmoxNetwork(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="networks")
    node = models.CharField(max_length=200)
    iface = models.CharField(max_length=200)
    kind = models.CharField(max_length=64, blank=True, default="")
    address = models.CharField(max_length=64, blank=True, default="")
    netmask = models.CharField(max_length=64, blank=True, default="")
    gateway = models.CharField(max_length=64, blank=True, default="")
    raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "node", "iface")]
        indexes = [models.Index(fields=["connection", "node"])]

    def __str__(self) -> str:
        return f"{self.connection}: {self.node} {self.iface}"


class ProxmoxCluster(models.Model):
    connection = models.OneToOneField(ProxmoxConnection, on_delete=models.CASCADE, related_name="cluster")
    raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.connection}: cluster"


class ProxmoxStorage(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="storages")
    node = models.CharField(max_length=200)
    storage = models.CharField(max_length=200)
    kind = models.CharField(max_length=64, blank=True, default="")
    status = models.CharField(max_length=32, blank=True, default="")
    total = models.BigIntegerField(null=True, blank=True)
    used = models.BigIntegerField(null=True, blank=True)
    avail = models.BigIntegerField(null=True, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "node", "storage")]
        indexes = [models.Index(fields=["connection", "node"])]

    def __str__(self) -> str:
        return f"{self.connection}: {self.node} storage {self.storage}"


class ProxmoxGuestIP(models.Model):
    SOURCE_AGENT = "agent"
    SOURCE_CONFIG = "config"
    SOURCE_CHOICES = [(SOURCE_AGENT, "Guest agent"), (SOURCE_CONFIG, "Config hint")]

    guest = models.ForeignKey(ProxmoxGuest, on_delete=models.CASCADE, related_name="ip_history")
    ip = models.CharField(max_length=128)
    source = models.CharField(max_length=16, choices=SOURCE_CHOICES, default=SOURCE_CONFIG)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("guest", "ip")]
        indexes = [models.Index(fields=["guest", "last_seen_at"])]

    def __str__(self) -> str:
        return f"{self.guest}: {self.ip}"


class ProxmoxPool(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="pools")
    poolid = models.CharField(max_length=200)
    comment = models.TextField(blank=True, default="")
    detail_raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "poolid")]
        indexes = [models.Index(fields=["connection", "poolid"])]

    def __str__(self) -> str:
        return f"{self.connection}: pool {self.poolid}"


class ProxmoxSdnZone(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="sdn_zones")
    zone = models.CharField(max_length=200)
    kind = models.CharField(max_length=64, blank=True, default="")
    raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "zone")]
        indexes = [models.Index(fields=["connection", "zone"])]

    def __str__(self) -> str:
        return f"{self.connection}: zone {self.zone}"


class ProxmoxSdnVnet(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="sdn_vnets")
    vnet = models.CharField(max_length=200)
    zone = models.CharField(max_length=200, blank=True, default="")
    alias = models.CharField(max_length=200, blank=True, default="")
    tag = models.IntegerField(null=True, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "vnet")]
        indexes = [models.Index(fields=["connection", "zone"])]

    def __str__(self) -> str:
        return f"{self.connection}: vnet {self.vnet}"


class ProxmoxSdnSubnet(models.Model):
    connection = models.ForeignKey(ProxmoxConnection, on_delete=models.CASCADE, related_name="sdn_subnets")
    subnet = models.CharField(max_length=200)
    vnet = models.CharField(max_length=200, blank=True, default="")
    gateway = models.CharField(max_length=64, blank=True, default="")
    raw = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("connection", "subnet")]
        indexes = [models.Index(fields=["connection", "vnet"])]

    def __str__(self) -> str:
        return f"{self.connection}: subnet {self.subnet}"
