from __future__ import annotations

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.core.models import Organization, Tag


class Checklist(models.Model):
    """
    Simple org-scoped checklist/runbook.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="checklists")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    tags = models.ManyToManyField(Tag, blank=True, related_name="checklists")
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_checklists_checklist_org_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "name"]),
            models.Index(fields=["organization", "archived_at"]),
            models.Index(fields=["organization", "-updated_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.organization}: {self.name}"


class ChecklistSchedule(models.Model):
    """
    Recurring schedule that creates ChecklistRuns.

    v1 supports:
    - Daily: every N days
    - Weekly: every N weeks, on selected weekdays
    - Monthly: every N months, on a specific day-of-month (or last day)

    next_run_on always points at the next scheduled date (local date).
    """

    REPEAT_DAILY = "daily"
    REPEAT_WEEKLY = "weekly"
    REPEAT_MONTHLY = "monthly"
    REPEAT_CHOICES = [
        (REPEAT_DAILY, "Daily"),
        (REPEAT_WEEKLY, "Weekly"),
        (REPEAT_MONTHLY, "Monthly"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="checklist_schedules")
    checklist = models.ForeignKey(Checklist, on_delete=models.CASCADE, related_name="schedules")
    name = models.CharField(max_length=200, help_text="Schedule name, e.g. Weekly backups review")
    enabled = models.BooleanField(default=True)

    # Legacy field (kept for backwards compatibility and migration). Prefer repeat_* fields.
    every_days = models.IntegerField(default=7, help_text="(Legacy) Create a run every N days.")
    repeat_unit = models.CharField(max_length=16, choices=REPEAT_CHOICES, default=REPEAT_DAILY)
    repeat_interval = models.IntegerField(default=7, help_text="Repeat every N units (days/weeks/months).")
    # Weekly: bitmask of selected weekdays where bit0=Mon ... bit6=Sun.
    weekly_days = models.IntegerField(default=0, help_text="(Weekly) Weekday bitmask (Mon..Sun).")
    # Monthly: day-of-month 1..31 (clamped to month length) or last-day flag.
    monthly_day = models.IntegerField(null=True, blank=True, help_text="(Monthly) Day of month (1-31).")
    monthly_on_last_day = models.BooleanField(default=False, help_text="(Monthly) Run on the last day of the month.")
    # Alignment anchor for interval math (set on create).
    anchor_on = models.DateField(null=True, blank=True, help_text="Anchor date for weekly/monthly interval alignment.")
    due_days = models.IntegerField(null=True, blank=True, help_text="Due date offset in days (blank = no due date).")
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_checklist_schedules",
    )

    next_run_on = models.DateField(help_text="Next scheduled run date.")
    last_created_at = models.DateTimeField(null=True, blank=True)

    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "name"],
                condition=Q(archived_at__isnull=True),
                name="uniq_checklists_schedule_org_name_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "enabled", "next_run_on"]),
            models.Index(fields=["organization", "checklist", "enabled"]),
            models.Index(fields=["organization", "archived_at"]),
        ]

    def save(self, *args, **kwargs):
        if self.checklist_id and (self.organization_id is None):
            self.organization_id = self.checklist.organization_id
        elif self.checklist_id and self.organization_id and self.organization_id != self.checklist.organization_id:
            self.organization_id = self.checklist.organization_id
        # Normalize repeat fields.
        if not self.repeat_unit:
            self.repeat_unit = self.REPEAT_DAILY
        if self.repeat_unit not in {self.REPEAT_DAILY, self.REPEAT_WEEKLY, self.REPEAT_MONTHLY}:
            self.repeat_unit = self.REPEAT_DAILY
        if self.repeat_interval is None or int(self.repeat_interval) <= 0:
            self.repeat_interval = 1
        self.repeat_interval = max(1, min(3650, int(self.repeat_interval)))

        # Keep legacy every_days aligned for daily schedules.
        if self.repeat_unit == self.REPEAT_DAILY:
            self.every_days = int(self.repeat_interval or 1)
        if self.every_days is None or int(self.every_days) <= 0:
            self.every_days = 1

        if self.anchor_on is None and self.next_run_on:
            self.anchor_on = self.next_run_on
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.organization}: Schedule({self.id}) {self.name}"

    @property
    def weekly_days_list(self) -> list[int]:
        mask = int(self.weekly_days or 0)
        out: list[int] = []
        for i in range(0, 7):
            if mask & (1 << i):
                out.append(i)
        return out

    @property
    def weekly_days_labels(self) -> str:
        labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        days = [labels[i] for i in self.weekly_days_list if 0 <= i <= 6]
        return ", ".join(days)

    @property
    def repeat_summary(self) -> str:
        unit = (self.repeat_unit or self.REPEAT_DAILY).lower()
        interval = int(self.repeat_interval or (self.every_days or 1) or 1)
        interval = max(1, interval)
        if unit == self.REPEAT_DAILY:
            return f"Every {interval} day(s)"
        if unit == self.REPEAT_WEEKLY:
            days = self.weekly_days_labels or "-"
            return f"Every {interval} week(s) on {days}"
        if unit == self.REPEAT_MONTHLY:
            if self.monthly_on_last_day:
                return f"Every {interval} month(s) on last day"
            day = int(self.monthly_day or 1)
            return f"Every {interval} month(s) on day {day}"
        return f"Every {interval} day(s)"


class ChecklistItem(models.Model):
    """
    Item within a checklist.

    We store organization_id directly to keep API/UI scoping simple.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="checklist_items")
    checklist = models.ForeignKey(Checklist, on_delete=models.CASCADE, related_name="items")
    text = models.CharField(max_length=400)
    is_done = models.BooleanField(default=False)
    sort_order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "checklist", "sort_order", "id"]),
            models.Index(fields=["organization", "is_done"]),
        ]

    def save(self, *args, **kwargs):
        if self.checklist_id and (self.organization_id is None):
            self.organization_id = self.checklist.organization_id
        elif self.checklist_id and self.organization_id and self.organization_id != self.checklist.organization_id:
            # Keep consistent; checklist defines org.
            self.organization_id = self.checklist.organization_id
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.organization}: {self.checklist_id}: {self.text[:80]}"


class ChecklistRun(models.Model):
    """
    A checklist "run" (execution instance), typically created from a Checklist template/runbook.
    """

    STATUS_OPEN = "open"
    STATUS_DONE = "done"
    STATUS_CANCELED = "canceled"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_DONE, "Done"),
        (STATUS_CANCELED, "Canceled"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="checklist_runs")
    checklist = models.ForeignKey(Checklist, on_delete=models.SET_NULL, null=True, blank=True, related_name="runs")
    schedule = models.ForeignKey(
        ChecklistSchedule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="runs",
        help_text="If set, this run was created by a recurring schedule.",
    )
    scheduled_for = models.DateField(null=True, blank=True, help_text="Scheduled date for runs created by a schedule.")
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN)
    due_on = models.DateField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="created_checklist_runs")
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_checklist_runs")

    # Optional generic link to an org-scoped object.
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.CharField(max_length=64, null=True, blank=True)
    content_object = GenericForeignKey("content_type", "object_id")

    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "schedule", "scheduled_for"],
                condition=Q(archived_at__isnull=True) & Q(schedule__isnull=False) & Q(scheduled_for__isnull=False),
                name="uniq_checklistrun_org_schedule_date_active",
            ),
        ]
        indexes = [
            models.Index(fields=["organization", "status", "due_on"]),
            models.Index(fields=["organization", "archived_at"]),
            models.Index(fields=["organization", "checklist", "-updated_at"]),
            models.Index(fields=["organization", "schedule", "scheduled_for"]),
        ]

    def mark_done(self):
        if self.status != self.STATUS_DONE:
            self.status = self.STATUS_DONE
        if self.completed_at is None:
            self.completed_at = timezone.now()
        if self.started_at is None:
            self.started_at = self.completed_at

    def mark_open(self):
        self.status = self.STATUS_OPEN
        self.completed_at = None
        if self.started_at is None:
            self.started_at = timezone.now()

    def __str__(self) -> str:
        return f"{self.organization}: Run({self.id}) {self.name}"


class ChecklistRunItem(models.Model):
    """
    Item within a ChecklistRun.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="checklist_run_items")
    run = models.ForeignKey(ChecklistRun, on_delete=models.CASCADE, related_name="items")
    checklist_item = models.ForeignKey(ChecklistItem, on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    text = models.CharField(max_length=400)
    is_done = models.BooleanField(default=False)
    sort_order = models.IntegerField(default=0)
    done_at = models.DateTimeField(null=True, blank=True)
    done_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="done_checklist_run_items")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "run", "sort_order", "id"]),
            models.Index(fields=["organization", "is_done"]),
        ]

    def save(self, *args, **kwargs):
        if self.run_id and (self.organization_id is None):
            self.organization_id = self.run.organization_id
        elif self.run_id and self.organization_id and self.organization_id != self.run.organization_id:
            self.organization_id = self.run.organization_id
        super().save(*args, **kwargs)

    def set_done(self, *, done: bool, user=None):
        done = bool(done)
        self.is_done = done
        if done:
            if self.done_at is None:
                self.done_at = timezone.now()
            if user is not None and self.done_by_id is None:
                self.done_by = user
        else:
            self.done_at = None
            self.done_by = None

    def __str__(self) -> str:
        return f"{self.organization}: RunItem({self.id})"
