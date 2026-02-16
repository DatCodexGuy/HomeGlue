from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.core.models import Organization, OrganizationMembership
from apps.docsapp.models import Document
from apps.versionsapp.models import ObjectVersion


class VersionsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)

    def test_document_create_update_creates_versions(self):
        d = Document.objects.create(organization=self.org, title="Runbook", body="v1")
        self.assertTrue(ObjectVersion.objects.filter(organization=self.org, object_id=str(d.id)).exists())

        d.body = "v2"
        d.save()
        self.assertGreaterEqual(ObjectVersion.objects.filter(organization=self.org, object_id=str(d.id)).count(), 2)
