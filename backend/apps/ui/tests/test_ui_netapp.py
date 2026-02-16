from __future__ import annotations

from datetime import date
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from apps.core.models import Organization, OrganizationMembership
from apps.netapp.models import Domain, SSLCertificate
from apps.netapp.public_info import CertLookup


class UiNetappAutoPopulateTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u", password="pw")
        self.org = Organization.objects.create(name="Org", description="")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

        self.client = Client(HTTP_HOST="localhost")
        assert self.client.login(username="u", password="pw")
        self.client.get(f"/app/orgs/{self.org.id}/enter/")

    @patch("apps.ui.views.lookup_tls_certificate")
    def test_ssl_create_auto_populates_and_sets_flash(self, m_lookup):
        m_lookup.return_value = CertLookup(
            issuer="CN=Issuer",
            serial_number="ABC",
            fingerprint_sha256="deadbeef",
            not_before=date(2026, 1, 1),
            not_after=date(2026, 12, 31),
            san_dns=["example.com", "www.example.com"],
            subject_cn="example.com",
        )

        r = self.client.post(
            "/app/ssl-certs/new/",
            {
                "_action": "create",
                "common_name": "example.com",
                "subject_alt_names": "",
                "issuer": "",
                "serial_number": "",
                "fingerprint_sha256": "",
                "not_before": "",
                "not_after": "",
                "notes": "",
                "domains": [],
                "tags": [],
            },
        )
        self.assertEqual(r.status_code, 302)
        cert = SSLCertificate.objects.get(organization=self.org, common_name="example.com")
        self.assertEqual(cert.issuer, "CN=Issuer")
        self.assertEqual(cert.not_after, date(2026, 12, 31))
        self.assertTrue(Domain.objects.filter(organization=self.org, name="example.com").exists())

        # First view after create should show flash and populated details.
        r2 = self.client.get(r["Location"])
        self.assertEqual(r2.status_code, 200)
        self.assertContains(r2, "Auto-filled certificate info", status_code=200)
        self.assertContains(r2, "CN=Issuer", status_code=200)

        # Flash should be one-time.
        r3 = self.client.get(r["Location"])
        self.assertEqual(r3.status_code, 200)
        self.assertNotContains(r3, "Auto-filled certificate info")

    @patch("apps.ui.views.lookup_domain_rdap")
    def test_domain_create_auto_populates_and_sets_flash(self, m_lookup):
        m_lookup.return_value = {"registrar": "Reg", "expires_on": date(2026, 11, 2)}

        r = self.client.post(
            "/app/domains/new/",
            {
                "_action": "create",
                "name": "example.com",
                "status": "active",
                "registrar": "",
                "dns_provider": "",
                "expires_on": "",
                "auto_renew": "0",
                "notes": "",
                "tags": [],
            },
        )
        self.assertEqual(r.status_code, 302)
        dom = Domain.objects.get(organization=self.org, name="example.com")
        self.assertEqual(dom.registrar, "Reg")
        self.assertEqual(dom.expires_on, date(2026, 11, 2))

        r2 = self.client.get(r["Location"])
        self.assertEqual(r2.status_code, 200)
        self.assertContains(r2, "Auto-filled domain info", status_code=200)
        self.assertContains(r2, "Reg", status_code=200)

