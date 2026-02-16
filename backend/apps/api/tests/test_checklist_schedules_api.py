from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.checklists.models import Checklist
from apps.core.models import Organization, OrganizationMembership


class ChecklistSchedulesApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", password="pw")
        self.member = User.objects.create_user(username="member", password="pw")

        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.admin, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)
        OrganizationMembership.objects.create(user=self.member, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

        self.chk = Checklist.objects.create(organization=self.org, name="Backups")

    def test_member_cannot_create_schedule(self):
        self.client.force_authenticate(user=self.member)
        resp = self.client.post(
            f"/api/checklist-schedules/?org={self.org.id}",
            data={
                "name": "Weekly Backups",
                "enabled": True,
                "checklist": self.chk.id,
                "every_days": 7,
                "next_run_on": timezone.localdate().isoformat(),
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_admin_can_create_schedule(self):
        self.client.force_authenticate(user=self.admin)
        resp = self.client.post(
            f"/api/checklist-schedules/?org={self.org.id}",
            data={
                "name": "Weekly Backups",
                "enabled": True,
                "checklist": self.chk.id,
                "every_days": 7,
                "due_days": 1,
                "next_run_on": timezone.localdate().isoformat(),
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.data)

        lst = self.client.get(f"/api/checklist-schedules/?org={self.org.id}")
        self.assertEqual(lst.status_code, 200, lst.data)
        names = [s["name"] for s in lst.data["results"]]
        self.assertEqual(names, ["Weekly Backups"])

