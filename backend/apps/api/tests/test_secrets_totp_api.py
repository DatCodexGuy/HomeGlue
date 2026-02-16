from __future__ import annotations

import re

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.core.models import Organization, OrganizationMembership
from apps.secretsapp.models import PasswordEntry


class SecretsTotpApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)
        self.client.force_authenticate(user=self.user)

    def test_enable_rotate_disable_and_code(self):
        p = PasswordEntry.objects.create(organization=self.org, created_by=self.user, name="P1", username="u")
        p.set_password("x")
        p.save(update_fields=["password_ciphertext"])

        r0 = self.client.post("/api/me/reauth/", data={"password": "pw"}, format="json")
        self.assertEqual(r0.status_code, 200, r0.data)
        token = r0.data["token"]
        hdrs = {"X-HomeGlue-Reauth": token}

        # Enable
        resp = self.client.post(f"/api/passwords/{p.id}/totp-enable/?org={self.org.id}", data={}, format="json", headers=hdrs)
        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertIn("secret", resp.data)
        self.assertIn("otpauth_url", resp.data)

        # Serializer reports has_totp
        resp2 = self.client.get(f"/api/passwords/{p.id}/?org={self.org.id}")
        self.assertEqual(resp2.status_code, 200, resp2.data)
        self.assertEqual(resp2.data["has_totp"], True)

        # Code
        resp3 = self.client.get(f"/api/passwords/{p.id}/totp-code/?org={self.org.id}", headers=hdrs)
        self.assertEqual(resp3.status_code, 200, resp3.data)
        self.assertTrue(re.fullmatch(r"\d{6}", resp3.data["code"]))
        self.assertTrue(0 <= int(resp3.data["remaining"]) <= 30)

        # Rotate
        resp4 = self.client.post(f"/api/passwords/{p.id}/totp-rotate/?org={self.org.id}", data={}, format="json", headers=hdrs)
        self.assertEqual(resp4.status_code, 200, resp4.data)
        self.assertIn("secret", resp4.data)

        # Disable
        resp5 = self.client.post(f"/api/passwords/{p.id}/totp-disable/?org={self.org.id}", data={}, format="json", headers=hdrs)
        self.assertEqual(resp5.status_code, 200, resp5.data)

        resp6 = self.client.get(f"/api/passwords/{p.id}/totp-code/?org={self.org.id}", headers=hdrs)
        self.assertEqual(resp6.status_code, 400, resp6.data)
