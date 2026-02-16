from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.core.models import Organization, OrganizationMembership


class RelationshipTypePermissionsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.client.force_authenticate(user=self.user)

        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

    def test_member_cannot_create_relationship_type(self):
        resp = self.client.post(
            f"/api/relationship-types/?org={self.org.id}",
            data={"name": "Runs On", "inverse_name": "Hosts", "symmetric": False},
            format="json",
        )
        self.assertEqual(resp.status_code, 403, resp.data)

