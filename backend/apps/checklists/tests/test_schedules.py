from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.checklists.management.commands.run_checklist_schedules_once import run_due_schedules
from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem, ChecklistSchedule
from apps.checklists.scheduling import next_occurrence_after
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
            repeat_unit=ChecklistSchedule.REPEAT_DAILY,
            repeat_interval=7,
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

    def test_weekly_schedule_advances_by_interval_and_weekday(self):
        chk = Checklist.objects.create(organization=self.org, name="Weekly review")
        today = timezone.localdate()
        # Only run on today's weekday, every 2 weeks.
        mask = 1 << int(today.weekday())
        sched = ChecklistSchedule.objects.create(
            organization=self.org,
            checklist=chk,
            name="Biweekly",
            enabled=True,
            repeat_unit=ChecklistSchedule.REPEAT_WEEKLY,
            repeat_interval=2,
            weekly_days=mask,
            next_run_on=today,
            anchor_on=today,
        )

        expected_next = next_occurrence_after(sched, today)
        res = run_due_schedules(org_id=self.org.id, limit=50)
        self.assertEqual(res.created_runs, 1)
        sched.refresh_from_db()
        self.assertEqual(sched.next_run_on, expected_next)

    def test_monthly_schedule_advances_to_next_month(self):
        chk = Checklist.objects.create(organization=self.org, name="Monthly close")
        today = timezone.localdate()
        sched = ChecklistSchedule.objects.create(
            organization=self.org,
            checklist=chk,
            name="Monthly",
            enabled=True,
            repeat_unit=ChecklistSchedule.REPEAT_MONTHLY,
            repeat_interval=1,
            monthly_day=int(today.day),
            monthly_on_last_day=False,
            next_run_on=today,
            anchor_on=today,
        )

        expected_next = next_occurrence_after(sched, today)
        res = run_due_schedules(org_id=self.org.id, limit=50)
        self.assertEqual(res.created_runs, 1)
        sched.refresh_from_db()
        self.assertEqual(sched.next_run_on, expected_next)
