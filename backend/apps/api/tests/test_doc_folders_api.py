from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.core.models import Organization, OrganizationMembership


class DocumentFoldersApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)
        self.client.force_authenticate(user=self.user)

    def test_crud_document_folders(self):
        # Create
        r = self.client.post(
            f"/api/document-folders/?org={self.org.id}",
            data={"name": "Runbooks", "parent": None},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        fid = r.data["id"]

        # List
        r2 = self.client.get(f"/api/document-folders/?org={self.org.id}")
        self.assertEqual(r2.status_code, 200, r2.data)
        names = [x["name"] for x in r2.data["results"]]
        self.assertIn("Runbooks", names)

        # Update
        r3 = self.client.patch(
            f"/api/document-folders/{fid}/?org={self.org.id}",
            data={"name": "Runbooks2"},
            format="json",
        )
        self.assertEqual(r3.status_code, 200, r3.data)
        self.assertEqual(r3.data["name"], "Runbooks2")

