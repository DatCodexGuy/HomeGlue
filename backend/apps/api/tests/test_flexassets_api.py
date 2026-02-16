from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from rest_framework.test import APIClient

from apps.assets.models import Asset
from apps.core.models import CustomField, Organization, OrganizationMembership
from apps.flexassets.models import FlexibleAssetType


class FlexAssetsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.client.force_authenticate(user=self.user)

        self.org1 = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org1, role=OrganizationMembership.ROLE_MEMBER)

    def test_flex_assets_require_org_context(self):
        resp = self.client.get("/api/flex-asset-types/")
        self.assertEqual(resp.status_code, 400, resp.data)

    def test_member_cannot_create_flex_asset_type(self):
        resp = self.client.post(f"/api/flex-asset-types/?org={self.org1.id}", data={"name": "Applications"}, format="json")
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_custom_field_flex_scope_requires_flexibleasset_content_type(self):
        # Member can't create custom fields via API anyway, but we can validate model-level scoping
        # by creating the field in DB and ensuring API rejects invalid updates would be covered elsewhere.
        # Here we at least ensure that the serializer includes flexible_asset_type and the viewset validates it.
        User = get_user_model()
        admin = User.objects.create_user(username="admin", password="pw")
        OrganizationMembership.objects.create(user=admin, organization=self.org1, role=OrganizationMembership.ROLE_ADMIN)
        self.client.force_authenticate(user=admin)

        t = FlexibleAssetType.objects.create(organization=self.org1, name="Applications")

        ct_asset = ContentType.objects.get_for_model(Asset)
        resp = self.client.post(
            f"/api/custom-fields/?org={self.org1.id}",
            data={"content_type": ct_asset.id, "flexible_asset_type": t.id, "key": "k1", "name": "K1", "field_type": CustomField.TYPE_TEXT},
            format="json",
        )
        self.assertEqual(resp.status_code, 400, resp.data)

