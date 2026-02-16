from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from apps.core.models import Organization, OrganizationMembership


class UiWorkflowsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u", password="pw")
        self.org = Organization.objects.create(name="Org", description="")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)

        self.client = Client(HTTP_HOST="localhost")
        assert self.client.login(username="u", password="pw")
        self.client.get(f"/app/orgs/{self.org.id}/enter/")

    def test_workflows_admin_can_create_rule(self):
        r = self.client.get("/app/workflows/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Workflows", status_code=200)

        r2 = self.client.post(
            "/app/workflows/new/",
            data={
                "name": "Domains expiring",
                "enabled": "on",
                "kind": "domain_expiry",
                "audience": "all",
                "run_interval_minutes": 60,
                "days": 30,
            },
        )
        self.assertEqual(r2.status_code, 302)

        # Landing page should render; "Run now" should not error.
        detail = self.client.get(r2["Location"])
        self.assertEqual(detail.status_code, 200)

        detail2 = self.client.post(r2["Location"], data={"_action": "run_now"})
        self.assertEqual(detail2.status_code, 200)
        self.assertContains(detail2, "Rule ran", status_code=200)

