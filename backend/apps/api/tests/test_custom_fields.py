from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from rest_framework.test import APIClient

from apps.assets.models import Asset
from apps.core.models import CustomField, Organization, OrganizationMembership


class CustomFieldsApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.client.force_authenticate(user=self.user)

        self.org1 = Organization.objects.create(name="Org 1")
        self.org2 = Organization.objects.create(name="Org 2")
        OrganizationMembership.objects.create(user=self.user, organization=self.org1, role=OrganizationMembership.ROLE_MEMBER)

        self.a1 = Asset.objects.create(organization=self.org1, name="A1")
        self.a2 = Asset.objects.create(organization=self.org2, name="A2")

        self.ct_asset = ContentType.objects.get_for_model(Asset)

    def test_custom_fields_require_org_context(self):
        resp = self.client.get("/api/custom-fields/")
        self.assertEqual(resp.status_code, 400, resp.data)

    def test_custom_fields_are_org_scoped(self):
        CustomField.objects.create(organization=self.org1, content_type=self.ct_asset, key="k1", name="K1")
        CustomField.objects.create(organization=self.org2, content_type=self.ct_asset, key="k2", name="K2")

        resp = self.client.get(f"/api/custom-fields/?org={self.org1.id}")
        self.assertEqual(resp.status_code, 200, resp.data)
        keys = [f["key"] for f in resp.data["results"]]
        self.assertEqual(keys, ["k1"])

    def test_member_cannot_create_custom_field(self):
        resp = self.client.post(
            f"/api/custom-fields/?org={self.org1.id}",
            data={"content_type": self.ct_asset.id, "key": "k1", "name": "K1", "field_type": CustomField.TYPE_TEXT},
            format="json",
        )
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_custom_field_value_create_and_filter_by_ref(self):
        field = CustomField.objects.create(
            organization=self.org1,
            content_type=self.ct_asset,
            key="warranty_expires",
            name="Warranty Expires",
            field_type=CustomField.TYPE_DATE,
        )

        resp = self.client.post(
            f"/api/custom-field-values/?org={self.org1.id}",
            data={"field": field.id, "ref": f"assets.asset:{self.a1.id}", "value_text": "2027-01-31"},
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.data)

        resp2 = self.client.get(f"/api/custom-field-values/?org={self.org1.id}&ref=assets.asset:{self.a1.id}")
        self.assertEqual(resp2.status_code, 200, resp2.data)
        self.assertEqual(len(resp2.data["results"]), 1)
        self.assertEqual(resp2.data["results"][0]["value_text"], "2027-01-31")

    def test_custom_field_value_cannot_point_to_other_org_object(self):
        field = CustomField.objects.create(organization=self.org1, content_type=self.ct_asset, key="k1", name="K1")
        resp = self.client.post(
            f"/api/custom-field-values/?org={self.org1.id}",
            data={"field": field.id, "ref": f"assets.asset:{self.a2.id}", "value_text": "x"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400, resp.data)

    def test_custom_field_value_requires_matching_content_type(self):
        field = CustomField.objects.create(organization=self.org1, content_type=self.ct_asset, key="k1", name="K1")
        # Use a mismatched ref (organization itself).
        resp = self.client.post(
            f"/api/custom-field-values/?org={self.org1.id}",
            data={"field": field.id, "ref": f"core.organization:{self.org1.id}", "value_text": "x"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400, resp.data)
