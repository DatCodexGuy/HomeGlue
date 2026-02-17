from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from apps.core.models import Organization, OrganizationMembership


class UiWikiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u", password="pw")
        self.org = Organization.objects.create(name="Org", description="")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

        self.client = Client(HTTP_HOST="localhost")
        assert self.client.login(username="u", password="pw")
        self.client.get(f"/app/orgs/{self.org.id}/enter/")

    def test_wiki_index_renders(self):
        r = self.client.get("/app/wiki/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Wiki", status_code=200)
        # Should have at least one shipped page.
        self.assertContains(r, "HomeGlue Documentation", status_code=200)

    def test_wiki_page_renders_markdown(self):
        r = self.client.get("/app/wiki/documentation/")
        self.assertEqual(r.status_code, 200)
        # Headings should render as HTML, not raw markdown.
        self.assertContains(r, "<h1", status_code=200)
        # Bold should render (this used to fail with the minimal renderer).
        self.assertContains(r, "<strong>", status_code=200)
        # Nested lists should render as nested <ul> blocks (regression for 2-space indentation).
        self.assertContains(r, "Inventory:<ul>", status_code=200)
        self.assertContains(r, "<li>Assets</li>", status_code=200)

    def test_public_wiki_is_accessible_without_login(self):
        c = Client(HTTP_HOST="localhost")
        r = c.get("/wiki/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Wiki", status_code=200)
        self.assertContains(r, "HomeGlue Documentation", status_code=200)

        r = c.get("/wiki/documentation/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "<h1", status_code=200)
