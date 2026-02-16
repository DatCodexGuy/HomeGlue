from __future__ import annotations

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.core.models import Organization, OrganizationMembership
from apps.netapp.models import Domain
from apps.workflows.models import Notification


class WorkflowsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", password="pw")
        self.member = User.objects.create_user(username="member", password="pw")
        self.other = User.objects.create_user(username="other", password="pw")

        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.admin, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)
        OrganizationMembership.objects.create(user=self.member, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)
        OrganizationMembership.objects.create(user=self.other, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

    def test_member_cannot_create_workflow_rule(self):
        self.client.force_authenticate(user=self.member)
        resp = self.client.post(
            f"/api/workflow-rules/?org={self.org.id}",
            data={
                "name": "Domains expiring",
                "enabled": True,
                "kind": "domain_expiry",
                "audience": "all",
                "days": 30,
                "run_interval_minutes": 60,
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_admin_can_run_rule_and_notifications_are_user_scoped(self):
        # Domain expiring soon so the rule generates notifications.
        Domain.objects.create(organization=self.org, name="example.com", expires_on=date.today() + timedelta(days=1))

        self.client.force_authenticate(user=self.admin)
        resp = self.client.post(
            f"/api/workflow-rules/?org={self.org.id}",
            data={
                "name": "Domains expiring",
                "enabled": True,
                "kind": "domain_expiry",
                "audience": "all",
                "days": 30,
                "run_interval_minutes": 60,
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.data)
        rule_id = resp.data["id"]

        run = self.client.post(f"/api/workflow-rules/{rule_id}/run_now/?org={self.org.id}", data={}, format="json")
        self.assertEqual(run.status_code, 200, run.data)
        self.assertGreaterEqual(int(run.data.get("notifications_created") or 0), 1)

        # Member can list only their own notifications.
        self.client.force_authenticate(user=self.member)
        lst = self.client.get(f"/api/notifications/?org={self.org.id}")
        self.assertEqual(lst.status_code, 200, lst.data)
        titles = [n["title"] for n in lst.data["results"]]
        self.assertTrue(any("Domain expiring" in t for t in titles), titles)

        # Create a notification for someone else; member should not see it.
        Notification.objects.create(
            organization=self.org,
            user=self.other,
            level=Notification.LEVEL_WARN,
            title="OtherUserOnly",
            body="x",
            dedupe_key="manual:other",
        )
        lst2 = self.client.get(f"/api/notifications/?org={self.org.id}")
        self.assertEqual(lst2.status_code, 200, lst2.data)
        titles2 = [n["title"] for n in lst2.data["results"]]
        self.assertNotIn("OtherUserOnly", titles2)

        # mark_read works (detail action)
        nid = lst2.data["results"][0]["id"]
        mr = self.client.post(f"/api/notifications/{nid}/mark_read/?org={self.org.id}", data={}, format="json")
        self.assertEqual(mr.status_code, 200, mr.data)
        self.assertIsNotNone(mr.data.get("read_at"))

