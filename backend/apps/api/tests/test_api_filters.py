from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.assets.models import Asset
from apps.core.models import Organization, OrganizationMembership, Tag


class ApiFilterTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(username="u", password="pw")
        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)
        self.client.force_authenticate(user=self.user)

    def test_q_search_filters_assets(self):
        Asset.objects.create(organization=self.org, name="Alpha Server")
        Asset.objects.create(organization=self.org, name="Printer")

        resp = self.client.get(f"/api/assets/?org={self.org.id}&q=Alpha")
        self.assertEqual(resp.status_code, 200, resp.data)
        names = [a["name"] for a in resp.data["results"]]
        self.assertEqual(names, ["Alpha Server"])

    def test_tag_filter_filters_assets(self):
        t = Tag.objects.create(organization=self.org, name="prod")
        a1 = Asset.objects.create(organization=self.org, name="A1")
        a2 = Asset.objects.create(organization=self.org, name="A2")
        a1.tags.add(t)

        resp = self.client.get(f"/api/assets/?org={self.org.id}&tag=prod")
        self.assertEqual(resp.status_code, 200, resp.data)
        names = [a["name"] for a in resp.data["results"]]
        self.assertEqual(names, ["A1"])

