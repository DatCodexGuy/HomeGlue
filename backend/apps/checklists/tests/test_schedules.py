from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.checklists.management.commands.run_checklist_schedules_once import run_due_schedules
from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem, ChecklistSchedule
from apps.core.models import Organization, OrganizationMembership


class ChecklistScheduleTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u", password="pw")
        self.org = Organization.objects.create(name="Org")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)

    def test_due_schedule_creates_run_and_advances_next_run(self):
        chk = Checklist.objects.create(organization=self.org, name="Backups")
        ChecklistItem.objects.create(organization=self.org, checklist=chk, text="Check backups", sort_order=1)
        ChecklistItem.objects.create(organization=self.org, checklist=chk, text="Verify restore", sort_order=2)

        today = timezone.localdate()
        sched = ChecklistSchedule.objects.create(
            organization=self.org,
            checklist=chk,
            name="Backups schedule",
            enabled=True,
            every_days=7,
            due_days=1,
            assigned_to=self.user,
            next_run_on=today,
        )

        res = run_due_schedules(org_id=self.org.id, limit=50)
        self.assertEqual(res.created_runs, 1)

        run = ChecklistRun.objects.get(organization=self.org, schedule=sched, scheduled_for=today)
        self.assertEqual(run.checklist_id, chk.id)
        self.assertEqual(run.assigned_to_id, self.user.id)
        self.assertEqual(run.due_on, today + timedelta(days=1))

        items = list(ChecklistRunItem.objects.filter(organization=self.org, run=run).order_by("sort_order", "id"))
        self.assertEqual([i.text for i in items], ["Check backups", "Verify restore"])

        sched.refresh_from_db()
        self.assertGreater(sched.next_run_on, today)

