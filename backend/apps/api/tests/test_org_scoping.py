from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.contrib.contenttypes.models import ContentType
from rest_framework.test import APIClient

from apps.assets.models import Asset
from apps.core.models import Organization, OrganizationMembership, RelationshipType, Relationship, Tag
from apps.netapp.models import Domain, SSLCertificate


class OrgScopingTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")

        self.org1 = Organization.objects.create(name="Org 1")
        self.org2 = Organization.objects.create(name="Org 2")

        OrganizationMembership.objects.create(user=self.user, organization=self.org1, role=OrganizationMembership.ROLE_MEMBER)

        self.client.force_authenticate(user=self.user)

    def test_organizations_list_is_membership_scoped(self):
        # User should not see org2 because they are not a member.
        resp = self.client.get("/api/organizations/")
        self.assertEqual(resp.status_code, 200, resp.data)
        ids = [o["id"] for o in resp.data["results"]]
        self.assertEqual(ids, [self.org1.id])

    def test_org_scoped_list_uses_single_membership_without_query_param(self):
        Asset.objects.create(organization=self.org1, name="A1")
        Asset.objects.create(organization=self.org2, name="A2")

        resp = self.client.get("/api/assets/")
        self.assertEqual(resp.status_code, 400, resp.data)

    def test_user_cannot_access_non_member_org_even_if_org_is_specified(self):
        resp = self.client.get(f"/api/assets/?org={self.org2.id}")
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_org_scoped_list_requires_explicit_org_context(self):
        Asset.objects.create(organization=self.org1, name="A1")
        resp = self.client.get(f"/api/assets/?org={self.org1.id}")
        self.assertEqual(resp.status_code, 200, resp.data)
        names = [a["name"] for a in resp.data["results"]]
        self.assertEqual(names, ["A1"])

        resp2 = self.client.get("/api/assets/", headers={"X-HomeGlue-Org": str(self.org1.id)})
        self.assertEqual(resp2.status_code, 200, resp2.data)
        names2 = [a["name"] for a in resp2.data["results"]]
        self.assertEqual(names2, ["A1"])

        resp3 = self.client.get(f"/api/orgs/{self.org1.id}/assets/")
        self.assertEqual(resp3.status_code, 200, resp3.data)
        names3 = [a["name"] for a in resp3.data["results"]]
        self.assertEqual(names3, ["A1"])

        resp4 = self.client.get(f"/api/orgs/{self.org2.id}/assets/")
        self.assertEqual(resp4.status_code, 403, resp4.data)

    def test_domains_and_sslcerts_are_org_scoped(self):
        Domain.objects.create(organization=self.org1, name="example.com")
        Domain.objects.create(organization=self.org2, name="other.com")
        SSLCertificate.objects.create(organization=self.org1, common_name="example.com", issuer="LetsEncrypt")
        SSLCertificate.objects.create(organization=self.org2, common_name="other.com", issuer="LetsEncrypt")

        resp = self.client.get("/api/domains/")
        self.assertEqual(resp.status_code, 400, resp.data)
        resp2 = self.client.get(f"/api/domains/?org={self.org1.id}")
        self.assertEqual(resp2.status_code, 200, resp2.data)
        self.assertEqual([d["name"] for d in resp2.data["results"]], ["example.com"])

        resp3 = self.client.get("/api/ssl-certs/")
        self.assertEqual(resp3.status_code, 400, resp3.data)
        resp4 = self.client.get(f"/api/ssl-certs/?org={self.org1.id}")
        self.assertEqual(resp4.status_code, 200, resp4.data)
        self.assertEqual([c["common_name"] for c in resp4.data["results"]], ["example.com"])

    def test_relationship_update_does_not_crash(self):
        # Regression test: RelationshipSerializer.update used to contain a stray password handler.
        rel_type = RelationshipType.objects.create(organization=self.org1, name="Runs On")
        a1 = Asset.objects.create(organization=self.org1, name="Asset 1")
        a2 = Asset.objects.create(organization=self.org1, name="Asset 2")

        ct = ContentType.objects.get_for_model(Asset)
        rel = Relationship.objects.create(
            organization=self.org1,
            relationship_type=rel_type,
            source_content_type=ct,
            source_object_id=str(a1.pk),
            target_content_type=ct,
            target_object_id=str(a2.pk),
        )

        resp = self.client.patch(
            f"/api/relationships/{rel.id}/?org={self.org1.id}",
            data={"notes": "updated"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.data)
        rel.refresh_from_db()
        self.assertEqual(rel.notes, "updated")

    def test_tags_are_global_plus_org_scoped(self):
        Tag.objects.create(name="global")  # global tag
        Tag.objects.create(organization=self.org1, name="org1-only")
        Tag.objects.create(organization=self.org2, name="org2-only")

        resp = self.client.get(f"/api/tags/?org={self.org1.id}")
        self.assertEqual(resp.status_code, 200, resp.data)
        names = [t["name"] for t in resp.data["results"]]
        self.assertEqual(set(names), {"global", "org1-only"})

        resp2 = self.client.get(f"/api/orgs/{self.org1.id}/tags/")
        self.assertEqual(resp2.status_code, 200, resp2.data)
        names2 = [t["name"] for t in resp2.data["results"]]
        self.assertEqual(set(names2), {"global", "org1-only"})
