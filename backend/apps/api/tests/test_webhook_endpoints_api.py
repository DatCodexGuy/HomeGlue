from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.core.models import Organization, OrganizationMembership


class WebhookEndpointsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", password="pw")
        self.member = User.objects.create_user(username="member", password="pw")

        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.admin, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)
        OrganizationMembership.objects.create(user=self.member, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

    def test_member_cannot_create_webhook_endpoint(self):
        self.client.force_authenticate(user=self.member)
        resp = self.client.post(
            f"/api/webhook-endpoints/?org={self.org.id}",
            data={"name": "Hook", "url": "https://example.com/hook", "enabled": True},
            format="json",
        )
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_admin_can_create_webhook_endpoint(self):
        self.client.force_authenticate(user=self.admin)
        resp = self.client.post(
            f"/api/webhook-endpoints/?org={self.org.id}",
            data={"name": "Hook", "url": "https://example.com/hook", "enabled": True, "secret": "s"},
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertTrue(resp.data.get("has_secret"))

