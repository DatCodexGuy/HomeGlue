from __future__ import annotations

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models

from apps.core.models import Organization
from apps.secretsapp.crypto import decrypt_str, encrypt_str


class WorkflowRule(models.Model):
    KIND_DOMAIN_EXPIRY = "domain_expiry"
    KIND_SSL_EXPIRY = "ssl_expiry"
    KIND_CHECKLIST_RUN_OVERDUE = "checklist_run_overdue"
    KIND_CONFIG_MISSING_PRIMARY_IP = "config_missing_primary_ip"
    KIND_ASSET_MISSING_LOCATION = "asset_missing_location"
    KIND_PASSWORD_MISSING_URL = "password_missing_url"
    KIND_PASSWORD_ROTATION_DUE = "password_rotation_due"
    KIND_BACKUP_FAILED_RECENT = "backup_failed_recent"
    KIND_PROXMOX_SYNC_STALE = "proxmox_sync_stale"

    KIND_CHOICES = [
        (KIND_DOMAIN_EXPIRY, "Domain expiry"),
        (KIND_SSL_EXPIRY, "SSL certificate expiry"),
        (KIND_CHECKLIST_RUN_OVERDUE, "Checklist run overdue"),
        (KIND_CONFIG_MISSING_PRIMARY_IP, "Config item missing primary IP"),
        (KIND_ASSET_MISSING_LOCATION, "Asset missing location"),
        (KIND_PASSWORD_MISSING_URL, "Password missing URL"),
        (KIND_PASSWORD_ROTATION_DUE, "Password rotation due"),
        (KIND_BACKUP_FAILED_RECENT, "Backup failures"),
        (KIND_PROXMOX_SYNC_STALE, "Proxmox sync stale"),
    ]

    AUDIENCE_ADMINS = "admins"
    AUDIENCE_ALL = "all"
    AUDIENCE_CHOICES = [
        (AUDIENCE_ADMINS, "Org admins"),
        (AUDIENCE_ALL, "All members"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="workflow_rules")
    name = models.CharField(max_length=200)
    enabled = models.BooleanField(default=True)
    kind = models.CharField(max_length=32, choices=KIND_CHOICES)
    audience = models.CharField(max_length=16, choices=AUDIENCE_CHOICES, default=AUDIENCE_ADMINS)
    params = models.JSONField(default=dict, blank=True)  # e.g. {"days": 30}
    run_interval_minutes = models.IntegerField(default=60, help_text="How often to evaluate this rule.")
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_run_ok = models.BooleanField(default=False)
    last_run_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["organization", "enabled", "kind", "updated_at"])]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class Notification(models.Model):
    LEVEL_INFO = "info"
    LEVEL_WARN = "warn"
    LEVEL_DANGER = "danger"

    LEVEL_CHOICES = [
        (LEVEL_INFO, "Info"),
        (LEVEL_WARN, "Warning"),
        (LEVEL_DANGER, "Danger"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="notifications")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    level = models.CharField(max_length=16, choices=LEVEL_CHOICES, default=LEVEL_WARN)
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True, default="")
    rule = models.ForeignKey(WorkflowRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="notifications")
    dedupe_key = models.CharField(max_length=255)
    read_at = models.DateTimeField(null=True, blank=True)

    # Optional generic link to an org-scoped object.
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.CharField(max_length=64, null=True, blank=True)
    content_object = GenericForeignKey("content_type", "object_id")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "user", "dedupe_key"], name="uniq_workflows_notification_dedupe"),
        ]
        indexes = [
            models.Index(fields=["organization", "user", "read_at", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.user}: {self.title}"


class WebhookEndpoint(models.Model):
    """
    Simple org-scoped webhook endpoint for workflow notifications.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="webhook_endpoints")
    name = models.CharField(max_length=200, default="Webhook")
    url = models.URLField()
    secret_ciphertext = models.TextField(blank=True, default="")
    verify_ssl = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["organization", "enabled", "updated_at"])]

    def set_secret(self, plaintext: str) -> None:
        self.secret_ciphertext = encrypt_str(plaintext or "")

    def get_secret(self) -> str:
        return decrypt_str(self.secret_ciphertext)

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class NotificationDeliveryAttempt(models.Model):
    KIND_EMAIL = "email"
    KIND_WEBHOOK = "webhook"
    KIND_CHOICES = [(KIND_EMAIL, "Email"), (KIND_WEBHOOK, "Webhook")]

    notification = models.ForeignKey(Notification, on_delete=models.CASCADE, related_name="delivery_attempts")
    kind = models.CharField(max_length=16, choices=KIND_CHOICES)
    endpoint = models.ForeignKey(WebhookEndpoint, on_delete=models.SET_NULL, null=True, blank=True, related_name="delivery_attempts")
    ok = models.BooleanField(default=False)
    status_code = models.IntegerField(null=True, blank=True)
    error = models.TextField(blank=True, default="")
    attempted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            # Idempotency: one attempt record per (notification, kind, endpoint) if it succeeded or failed.
            models.UniqueConstraint(fields=["notification", "kind", "endpoint"], name="uniq_workflows_delivery_attempt"),
        ]
        indexes = [
            models.Index(fields=["kind", "ok", "-attempted_at"]),
            models.Index(fields=["notification", "kind", "ok"]),
        ]

    def __str__(self) -> str:
        return f"{self.notification}: {self.kind} ok={self.ok}"


class WorkflowRuleRun(models.Model):
    """
    Historic execution record for workflow rule evaluations.

    This is intentionally "append only" for operational troubleshooting:
    - When did the rule run?
    - Did it error?
    - How many notifications were created?
    - Was it manual/worker/ops triggered?
    """

    TRIGGER_WORKER = "worker"
    TRIGGER_MANUAL = "manual"
    TRIGGER_OPS = "ops"
    TRIGGER_CHOICES = [
        (TRIGGER_WORKER, "Worker"),
        (TRIGGER_MANUAL, "Manual"),
        (TRIGGER_OPS, "Ops"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="workflow_rule_runs")
    rule = models.ForeignKey(WorkflowRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="runs")
    triggered_by = models.CharField(max_length=16, choices=TRIGGER_CHOICES, default=TRIGGER_WORKER)
    triggered_by_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="triggered_workflow_rule_runs",
    )

    started_at = models.DateTimeField()
    finished_at = models.DateTimeField()
    duration_ms = models.IntegerField(default=0)
    ok = models.BooleanField(default=False)
    notifications_created = models.IntegerField(default=0)
    error = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "-started_at"], name="idx_wf_rule_run_org_recent"),
            models.Index(fields=["organization", "rule", "-started_at"], name="idx_wf_rule_run_rule_recent"),
            models.Index(fields=["organization", "ok", "-started_at"], name="idx_wf_rule_run_ok_recent"),
        ]

    def __str__(self) -> str:
        rid = str(self.rule_id) if self.rule_id else "?"
        return f"{self.organization}: rule={rid} ok={self.ok} at={self.started_at}"
