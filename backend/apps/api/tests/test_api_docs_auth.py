from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient


class ApiDocsAuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_schema_requires_auth(self):
        r = self.client.get("/api/schema/")
        self.assertIn(r.status_code, {401, 403})

        User = get_user_model()
        u = User.objects.create_user(username="u", password="pw")
        self.client.force_authenticate(user=u)
        r2 = self.client.get("/api/schema/")
        self.assertEqual(r2.status_code, 200)

