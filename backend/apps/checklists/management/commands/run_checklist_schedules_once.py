from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from apps.checklists.models import ChecklistRun, ChecklistSchedule
from apps.checklists.scheduling import advance_next_run_on
from apps.checklists.services import copy_checklist_items_to_run


@dataclass(frozen=True)
class ScheduleRunResult:
    created_runs: int = 0
    advanced_schedules: int = 0


def run_due_schedules(*, org_id: int | None = None, limit: int = 200) -> ScheduleRunResult:
    today = timezone.localdate()
    now = timezone.now()

    qs = ChecklistSchedule.objects.select_related("organization", "checklist", "assigned_to").filter(
        enabled=True,
        archived_at__isnull=True,
        next_run_on__isnull=False,
        next_run_on__lte=today,
    )
    if org_id:
        qs = qs.filter(organization_id=int(org_id))

    created_runs = 0
    advanced = 0

    for sched in qs.order_by("next_run_on", "id")[: int(limit or 200)]:
        with transaction.atomic():
            sched = ChecklistSchedule.objects.select_for_update().select_related("organization", "checklist").get(pk=sched.pk)
            if not sched.enabled or sched.archived_at is not None or not sched.next_run_on:
                continue

            # If the underlying checklist is archived, just advance the schedule.
            if sched.checklist.archived_at is not None:
                if advance_next_run_on(schedule=sched, today=today).changed:
                    sched.save(update_fields=["next_run_on", "updated_at"])
                    advanced += 1
                continue

            scheduled_for = sched.next_run_on
            defaults = {
                "checklist": sched.checklist,
                "name": (sched.name or sched.checklist.name)[:200],
                "assigned_to": sched.assigned_to,
                "scheduled_for": scheduled_for,
            }
            due_days = sched.due_days
            if due_days is not None:
                try:
                    defaults["due_on"] = scheduled_for + timedelta(days=int(due_days))
                except Exception:
                    pass

            run, was_created = ChecklistRun.objects.get_or_create(
                organization=sched.organization,
                schedule=sched,
                scheduled_for=scheduled_for,
                defaults=defaults,
            )
            if was_created and run.checklist_id:
                copy_checklist_items_to_run(org=sched.organization, run=run, checklist=sched.checklist)
                created_runs += 1
                sched.last_created_at = now

            res = advance_next_run_on(schedule=sched, today=today)
            if res.changed:
                advanced += 1

            sched.save(update_fields=["next_run_on", "last_created_at", "updated_at"])

    return ScheduleRunResult(created_runs=created_runs, advanced_schedules=advanced)


class Command(BaseCommand):
    help = "Create checklist runs for due recurring schedules."

    def add_arguments(self, parser):
        parser.add_argument("--org-id", type=int, default=None, help="Limit to a single organization.")
        parser.add_argument("--limit", type=int, default=200, help="Max schedules to process per run.")

    def handle(self, *args, **opts):
        org_id = opts.get("org_id")
        limit = int(opts.get("limit") or 200)
        res = run_due_schedules(org_id=int(org_id) if org_id else None, limit=limit)
        self.stdout.write(f"checklist schedules: created_runs={res.created_runs} advanced_schedules={res.advanced_schedules}")
