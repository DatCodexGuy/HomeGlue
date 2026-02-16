from __future__ import annotations

from django.test import TestCase, override_settings


class IpAccessControlTests(TestCase):
    @override_settings(HOMEGLUE_IP_ALLOWLIST="10.0.0.0/24")
    def test_denied_when_not_in_allowlist(self):
        r = self.client.get("/app/", REMOTE_ADDR="192.168.1.10")
        self.assertEqual(r.status_code, 403)

    @override_settings(HOMEGLUE_IP_ALLOWLIST="10.0.0.0/24")
    def test_allowed_when_in_allowlist(self):
        r = self.client.get("/app/", REMOTE_ADDR="10.0.0.42")
        # /app/ redirects to login when unauthenticated, but should not be forbidden.
        self.assertIn(r.status_code, {200, 302})

    @override_settings(HOMEGLUE_IP_BLOCKLIST="10.0.0.42/32")
    def test_blocklist_denies(self):
        r = self.client.get("/app/", REMOTE_ADDR="10.0.0.42")
        self.assertEqual(r.status_code, 403)

