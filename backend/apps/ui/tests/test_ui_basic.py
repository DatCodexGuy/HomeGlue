from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from apps.core.models import Organization, OrganizationMembership, UserProfile


class UiBasicTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u", password="pw")
        self.org = Organization.objects.create(name="Org", description="")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

        self.client = Client(HTTP_HOST="localhost")
        assert self.client.login(username="u", password="pw")

    def test_enter_org_sets_session_and_dashboard_renders(self):
        r = self.client.get("/app/")
        self.assertContains(r, "Pick an organization", status_code=200)

        r = self.client.get(f"/app/orgs/{self.org.id}/enter/")
        self.assertEqual(r.status_code, 302)

        r = self.client.get("/app/dashboard/")
        self.assertContains(r, "Org", status_code=200)

    def test_org_required_redirects_to_picker_and_preserves_next(self):
        # Accessing org-scoped pages without an entered org should bounce to the picker.
        r = self.client.get("/app/assets/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/app/?next=%2Fapp%2Fassets%2F", r["Location"])

        r = self.client.get("/app/?next=/app/assets/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, f"/app/orgs/{self.org.id}/enter/?next=%2Fapp%2Fassets%2F")

        r = self.client.get(f"/app/orgs/{self.org.id}/enter/?next=/app/assets/")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r["Location"], "/app/assets/")

    def test_settings_can_set_default_org(self):
        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        r = self.client.post("/app/settings/", {"_action": "set_default_org"})
        self.assertEqual(r.status_code, 302)

        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual(profile.default_organization_id, self.org.id)

    def test_relationship_detail_renders(self):
        from django.contrib.contenttypes.models import ContentType
        from apps.assets.models import Asset
        from apps.core.models import RelationshipType, Relationship

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        rt = RelationshipType.objects.create(organization=self.org, name="Runs On")
        a1 = Asset.objects.create(organization=self.org, name="A1")
        a2 = Asset.objects.create(organization=self.org, name="A2")
        ct = ContentType.objects.get_for_model(Asset)
        rel = Relationship.objects.create(
            organization=self.org,
            relationship_type=rt,
            source_content_type=ct,
            source_object_id=str(a1.id),
            target_content_type=ct,
            target_object_id=str(a2.id),
        )

        r = self.client.get(f"/app/relationships/{rel.id}/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Relationship", status_code=200)

    def test_search_finds_asset(self):
        from apps.assets.models import Asset

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        Asset.objects.create(organization=self.org, name="SearchMe")
        r = self.client.get("/app/search/?q=SearchMe")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "SearchMe", status_code=200)

    def test_asset_delete_flow(self):
        from apps.assets.models import Asset

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        OrganizationMembership.objects.filter(user=self.user, organization=self.org).update(role=OrganizationMembership.ROLE_ADMIN)
        a = Asset.objects.create(organization=self.org, name="DeleteMe")
        r = self.client.get(f"/app/assets/{a.id}/delete/")
        self.assertEqual(r.status_code, 200)
        r = self.client.post(f"/app/assets/{a.id}/delete/", {"confirm": "1"})
        self.assertEqual(r.status_code, 302)
        a.refresh_from_db()
        self.assertIsNotNone(a.archived_at)

    def test_relationships_list_can_filter_by_ref(self):
        from django.contrib.contenttypes.models import ContentType
        from apps.assets.models import Asset
        from apps.core.models import Relationship, RelationshipType

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        rt = RelationshipType.objects.create(organization=self.org, name="Linked")
        a1 = Asset.objects.create(organization=self.org, name="FilterMe")
        a2 = Asset.objects.create(organization=self.org, name="OtherAsset")
        a3 = Asset.objects.create(organization=self.org, name="ThirdAsset")
        ct = ContentType.objects.get_for_model(Asset)

        Relationship.objects.create(
            organization=self.org,
            relationship_type=rt,
            source_content_type=ct,
            source_object_id=str(a1.id),
            target_content_type=ct,
            target_object_id=str(a2.id),
        )
        Relationship.objects.create(
            organization=self.org,
            relationship_type=rt,
            source_content_type=ct,
            source_object_id=str(a2.id),
            target_content_type=ct,
            target_object_id=str(a3.id),
        )

        ref = f"{ct.app_label}.{ct.model}:{a1.id}"
        r = self.client.get(f"/app/relationships/?ref={ref}")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "FilterMe", status_code=200)
        self.assertContains(r, "OtherAsset", status_code=200)
        self.assertNotContains(r, "ThirdAsset")

    def test_object_delete_cleans_up_generic_refs(self):
        from django.contrib.contenttypes.models import ContentType
        from django.core.files.uploadedfile import SimpleUploadedFile

        from apps.assets.models import Asset
        from apps.core.models import Attachment, CustomField, CustomFieldValue, Note

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        OrganizationMembership.objects.filter(user=self.user, organization=self.org).update(role=OrganizationMembership.ROLE_ADMIN)
        a = Asset.objects.create(organization=self.org, name="CleanupMe")
        ct = ContentType.objects.get_for_model(Asset)

        Attachment.objects.create(
            organization=self.org,
            file=SimpleUploadedFile("t.txt", b"hi", content_type="text/plain"),
            content_type=ct,
            object_id=str(a.id),
        )

        f = CustomField.objects.create(organization=self.org, content_type=ct, key="k", name="K")
        CustomFieldValue.objects.create(organization=self.org, field=f, content_type=ct, object_id=str(a.id), value_text="v")
        Note.objects.create(organization=self.org, title="T", body="B", content_type=ct, object_id=str(a.id), created_by=self.user)

        r = self.client.post(f"/app/assets/{a.id}/delete/", {"confirm": "1"})
        self.assertEqual(r.status_code, 302)
        a.refresh_from_db()
        self.assertIsNotNone(a.archived_at)
        self.assertTrue(Attachment.objects.filter(organization=self.org, content_type=ct, object_id=str(a.id)).exists())
        self.assertTrue(CustomFieldValue.objects.filter(organization=self.org, content_type=ct, object_id=str(a.id)).exists())
        self.assertTrue(Note.objects.filter(organization=self.org, content_type=ct, object_id=str(a.id)).exists())

        # Restore and ensure it's active again.
        r = self.client.post("/app/objects/restore/", {"ref": f"{ct.app_label}.{ct.model}:{a.id}", "next": f"/app/assets/{a.id}/"})
        self.assertEqual(r.status_code, 302)
        a.refresh_from_db()
        self.assertIsNone(a.archived_at)

    def test_notes_can_attach_to_asset_and_render(self):
        from apps.assets.models import Asset
        from apps.core.models import Note
        from django.contrib.contenttypes.models import ContentType

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        a = Asset.objects.create(organization=self.org, name="NoteAsset")
        ct = ContentType.objects.get_for_model(Asset)

        r = self.client.post(
            "/app/notes/add/",
            {"title": "Hello", "body": "World", "ref": f"{ct.app_label}.{ct.model}:{a.id}", "next": f"/app/assets/{a.id}/"},
        )
        self.assertEqual(r.status_code, 302)
        self.assertTrue(Note.objects.filter(organization=self.org, title="Hello", content_type=ct, object_id=str(a.id)).exists())

        r = self.client.get(f"/app/assets/{a.id}/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Hello", status_code=200)
        self.assertContains(r, "World", status_code=200)

    def test_bulk_delete_assets(self):
        from apps.assets.models import Asset

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        OrganizationMembership.objects.filter(user=self.user, organization=self.org).update(role=OrganizationMembership.ROLE_ADMIN)
        a1 = Asset.objects.create(organization=self.org, name="B1")
        a2 = Asset.objects.create(organization=self.org, name="B2")
        r = self.client.post("/app/assets/bulk/", {"action": "archive", "ids": [str(a1.id), str(a2.id)], "next": "/app/assets/"})
        self.assertEqual(r.status_code, 302)
        a1.refresh_from_db()
        a2.refresh_from_db()
        self.assertIsNotNone(a1.archived_at)
        self.assertIsNotNone(a2.archived_at)

    def test_document_can_be_flagged(self):
        from apps.docsapp.models import Document

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        d = Document.objects.create(organization=self.org, title="FlagMe", body="x", created_by=self.user)

        r = self.client.post(f"/app/documents/{d.id}/", {"_action": "toggle_flag"})
        self.assertEqual(r.status_code, 302)
        d.refresh_from_db()
        self.assertIsNotNone(d.flagged_at)

    def test_docs_and_passwords_acl_visibility(self):
        from django.contrib.auth import get_user_model
        from apps.docsapp.models import Document
        from apps.secretsapp.models import PasswordEntry

        User = get_user_model()
        other = User.objects.create_user(username="v", password="pw")
        OrganizationMembership.objects.create(user=other, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

        self.client.get(f"/app/orgs/{self.org.id}/enter/")

        doc_private = Document.objects.create(
            organization=self.org,
            created_by=other,
            visibility=Document.VIS_PRIVATE,
            title="TopSecretDoc",
            body="x",
        )
        pw_private = PasswordEntry.objects.create(
            organization=self.org,
            created_by=other,
            visibility=PasswordEntry.VIS_PRIVATE,
            name="TopSecretPw",
            username="u",
        )
        pw_private.set_password("Secret123")
        pw_private.save(update_fields=["password_ciphertext"])

        r = self.client.get("/app/documents/")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "TopSecretDoc")

        r = self.client.get(f"/app/documents/{doc_private.id}/")
        self.assertEqual(r.status_code, 404)

        r = self.client.get("/app/passwords/")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "TopSecretPw")

        r = self.client.get(f"/app/passwords/{pw_private.id}/")
        self.assertEqual(r.status_code, 404)

        # Share and ensure it becomes visible.
        doc_shared = Document.objects.create(
            organization=self.org,
            created_by=other,
            visibility=Document.VIS_SHARED,
            title="SharedDoc",
            body="y",
        )
        doc_shared.allowed_users.add(self.user)

        pw_shared = PasswordEntry.objects.create(
            organization=self.org,
            created_by=other,
            visibility=PasswordEntry.VIS_SHARED,
            name="SharedPw",
            username="u",
        )
        pw_shared.allowed_users.add(self.user)
        pw_shared.set_password("S2")
        pw_shared.save(update_fields=["password_ciphertext"])

        r = self.client.get("/app/documents/")
        self.assertContains(r, "SharedDoc", status_code=200)
        r = self.client.get(f"/app/documents/{doc_shared.id}/")
        self.assertEqual(r.status_code, 200)

        r = self.client.get("/app/passwords/")
        self.assertContains(r, "SharedPw", status_code=200)

        # Sensitive actions require a fresh re-auth.
        r = self.client.post("/app/reauth/?next=/app/passwords/", {"password": "pw"})
        self.assertEqual(r.status_code, 302)
        r = self.client.post(f"/app/passwords/{pw_shared.id}/", {"_action": "reveal"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "S2", status_code=200)

    def test_password_totp_enable_and_code_endpoint(self):
        import json
        import re

        from apps.secretsapp.models import PasswordEntry

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        p = PasswordEntry.objects.create(organization=self.org, created_by=self.user, name="P", username="u")
        p.set_password("x")
        p.save(update_fields=["password_ciphertext"])

        r0 = self.client.post(f"/app/reauth/?next=/app/passwords/{p.id}/", {"password": "pw"})
        self.assertEqual(r0.status_code, 302)

        r = self.client.post(f"/app/passwords/{p.id}/", {"_action": "enable_totp"})
        self.assertEqual(r.status_code, 302)

        r2 = self.client.get(f"/app/passwords/{p.id}/totp/")
        self.assertEqual(r2.status_code, 200)
        data = json.loads(r2.content.decode("utf-8"))
        self.assertTrue(re.fullmatch(r"\d{6}", data["code"]))
        self.assertTrue(0 <= int(data["remaining"]) <= 30)

        r3 = self.client.post(f"/app/passwords/{p.id}/", {"_action": "disable_totp"})
        self.assertEqual(r3.status_code, 302)
        r4 = self.client.get(f"/app/passwords/{p.id}/totp/")
        self.assertEqual(r4.status_code, 404)

    def test_document_folders_basic_flow(self):
        from apps.docsapp.models import Document, DocumentFolder

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        f = DocumentFolder.objects.create(organization=self.org, name="Runbooks")
        d = Document.objects.create(organization=self.org, created_by=self.user, title="Doc1", body="x", folder=f)

        r = self.client.get("/app/document-folders/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Runbooks", status_code=200)

        r2 = self.client.get(f"/app/document-folders/{f.id}/")
        self.assertEqual(r2.status_code, 200)
        self.assertContains(r2, "Doc1", status_code=200)

        r3 = self.client.get("/app/documents/")
        self.assertEqual(r3.status_code, 200)
        self.assertContains(r3, "Runbooks", status_code=200)

        r4 = self.client.get(f"/app/documents/?folder={f.id}")
        self.assertEqual(r4.status_code, 200)
        self.assertContains(r4, "Doc1", status_code=200)

    def test_relationships_mask_restricted_endpoints(self):
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType
        from apps.assets.models import Asset
        from apps.core.models import Relationship, RelationshipType
        from apps.docsapp.models import Document

        User = get_user_model()
        other = User.objects.create_user(username="v2", password="pw")
        OrganizationMembership.objects.create(user=other, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        rt = RelationshipType.objects.create(organization=self.org, name="Linked")
        a1 = Asset.objects.create(organization=self.org, name="A1")
        d1 = Document.objects.create(organization=self.org, created_by=other, visibility=Document.VIS_PRIVATE, title="HiddenDoc", body="x")

        ct_asset = ContentType.objects.get_for_model(Asset)
        ct_doc = ContentType.objects.get_for_model(Document)
        Relationship.objects.create(
            organization=self.org,
            relationship_type=rt,
            source_content_type=ct_asset,
            source_object_id=str(a1.id),
            target_content_type=ct_doc,
            target_object_id=str(d1.id),
        )

        r = self.client.get("/app/relationships/")
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "HiddenDoc")
        self.assertContains(r, "(restricted)")

    def test_saved_view_applies_q_when_no_explicit_q(self):
        from apps.assets.models import Asset
        from apps.core.models import SavedView

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        Asset.objects.create(organization=self.org, name="Alpha")
        Asset.objects.create(organization=self.org, name="Bravo")

        sv = SavedView.objects.create(
            organization=self.org,
            model_key=SavedView.KEY_ASSET,
            name="Only Bravo",
            params={"q": "Bravo"},
            created_by=self.user,
        )

        r = self.client.get(f"/app/assets/?view={sv.id}")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Bravo", status_code=200)
        self.assertNotContains(r, "Alpha")

    def test_assets_export_csv(self):
        from apps.assets.models import Asset

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        Asset.objects.create(organization=self.org, name="ExportMe")
        r = self.client.get("/app/assets/export.csv")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "name,type,manufacturer,model,serial_number,location", status_code=200)
        self.assertContains(r, "ExportMe", status_code=200)

    def test_assets_import_csv_upserts(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.assets.models import Asset

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        csv_bytes = b"name,type,manufacturer,model,serial_number,location\nA1,server,Dell,R740,SN1,HQ\n"
        f = SimpleUploadedFile("assets.csv", csv_bytes, content_type="text/csv")
        r = self.client.post("/app/assets/import/", {"file": f})
        self.assertEqual(r.status_code, 200)
        a = Asset.objects.get(organization=self.org, name="A1")
        self.assertEqual(a.asset_type, Asset.TYPE_SERVER)
        self.assertEqual(a.manufacturer, "Dell")

    def test_contacts_import_csv_creates(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.people.models import Contact

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        csv_bytes = b"first_name,last_name,email,phone,title\nJane,Doe,jane@example.com,555-0000,CTO\n"
        f = SimpleUploadedFile("contacts.csv", csv_bytes, content_type="text/csv")
        r = self.client.post("/app/contacts/import/", {"file": f})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(Contact.objects.filter(organization=self.org, email="jane@example.com").exists())

    def test_config_items_import_csv_upserts(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.assets.models import ConfigurationItem

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        csv_bytes = b"name,type,hostname,primary_ip,operating_system\nCI1,server,ci1,10.0.0.10,Ubuntu\n"
        f = SimpleUploadedFile("cis.csv", csv_bytes, content_type="text/csv")
        r = self.client.post("/app/config-items/import/", {"file": f})
        self.assertEqual(r.status_code, 200)
        obj = ConfigurationItem.objects.get(organization=self.org, name="CI1")
        self.assertEqual(obj.ci_type, ConfigurationItem.TYPE_SERVER)
        self.assertEqual(obj.hostname, "ci1")

    def test_quick_palette_json(self):
        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        r = self.client.get("/app/quick/?q=abc")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "\"items\"", status_code=200)

    def test_templates_import_csv_upserts(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.docsapp.models import DocumentTemplate

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        csv_bytes = b"name,body\nT1,Hello\n"
        f = SimpleUploadedFile("tmpls.csv", csv_bytes, content_type="text/csv")
        r = self.client.post("/app/templates/import/", {"file": f})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(DocumentTemplate.objects.filter(organization=self.org, name="T1").exists())

    def test_documents_import_csv_creates_and_links_template(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.docsapp.models import Document, DocumentTemplate

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        csv_bytes = b"title,body,template\nD1,Body,T2\n"
        f = SimpleUploadedFile("docs.csv", csv_bytes, content_type="text/csv")
        r = self.client.post("/app/documents/import/", {"file": f})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(Document.objects.filter(organization=self.org, title="D1").exists())
        doc = Document.objects.get(organization=self.org, title="D1")
        self.assertIsNotNone(doc.template_id)
        self.assertTrue(DocumentTemplate.objects.filter(organization=self.org, name="T2").exists())

    def test_passwords_import_csv_sets_password(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.secretsapp.models import PasswordEntry

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        csv_bytes = b"name,username,url,notes,password\nP1,u,https://x,Note,Secret123\n"
        f = SimpleUploadedFile("p.csv", csv_bytes, content_type="text/csv")
        r = self.client.post("/app/passwords/import/", {"file": f})
        self.assertEqual(r.status_code, 200)
        p = PasswordEntry.objects.get(organization=self.org, name="P1")
        self.assertEqual(p.get_password(), "Secret123")

    def test_checklists_create_and_toggle_item(self):
        from apps.checklists.models import Checklist, ChecklistItem

        self.client.get(f"/app/orgs/{self.org.id}/enter/")

        r = self.client.post("/app/checklists/new/", {"name": "Runbook A", "description": "D"})
        self.assertEqual(r.status_code, 302)
        chk = Checklist.objects.get(organization=self.org, name="Runbook A")

        r = self.client.post(f"/app/checklists/{chk.id}/", {"_action": "add_item", "text": "Step 1"})
        self.assertEqual(r.status_code, 302)
        it = ChecklistItem.objects.get(organization=self.org, checklist=chk, text="Step 1")
        self.assertFalse(it.is_done)

        r = self.client.post(f"/app/checklists/{chk.id}/", {"_action": "toggle_item", "item_id": str(it.id)})
        self.assertEqual(r.status_code, 302)
        it.refresh_from_db()
        self.assertTrue(it.is_done)

    def test_checklist_run_can_be_started_and_items_toggled(self):
        from apps.checklists.models import Checklist, ChecklistItem, ChecklistRun, ChecklistRunItem

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        chk = Checklist.objects.create(organization=self.org, name="CB", description="")
        ChecklistItem.objects.create(organization=self.org, checklist=chk, text="Step A", sort_order=1)

        # Start run from checklist (redirects to run creation).
        r = self.client.get(f"/app/checklists/{chk.id}/runs/new/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/app/checklist-runs/new/", r["Location"])

        # Create the run (copying items).
        r = self.client.post("/app/checklist-runs/new/?checklist_id=%d" % chk.id, {"name": "Run1"})
        self.assertEqual(r.status_code, 302)
        run = ChecklistRun.objects.get(organization=self.org, name="Run1")
        self.assertEqual(run.checklist_id, chk.id)
        it = ChecklistRunItem.objects.get(organization=self.org, run=run)
        self.assertEqual(it.text, "Step A")

        # Toggle item done.
        r = self.client.post(f"/app/checklist-runs/{run.id}/", {"_action": "toggle_item", "item_id": str(it.id)})
        self.assertEqual(r.status_code, 302)
        it.refresh_from_db()
        self.assertTrue(it.is_done)

    def test_password_folder_can_be_created_and_used(self):
        from apps.secretsapp.models import PasswordEntry, PasswordFolder

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        r = self.client.post("/app/password-folders/new/", {"name": "FolderA"})
        self.assertEqual(r.status_code, 302)
        f = PasswordFolder.objects.get(organization=self.org, name="FolderA")

        r = self.client.post("/app/passwords/new/", {"name": "P1", "folder": str(f.id), "visibility": "admins"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(PasswordEntry.objects.filter(organization=self.org, name="P1", folder=f).exists())

    def test_file_safeshare_one_time_download(self):
        from urllib.parse import urlsplit
        from django.contrib.contenttypes.models import ContentType
        from django.core.files.uploadedfile import SimpleUploadedFile
        from apps.assets.models import Asset
        from apps.core.models import Attachment, AttachmentShareLink
        from apps.core.reauth import mark_session_reauthed

        self.client.get(f"/app/orgs/{self.org.id}/enter/")
        OrganizationMembership.objects.filter(user=self.user, organization=self.org).update(role=OrganizationMembership.ROLE_ADMIN)
        sess = self.client.session
        mark_session_reauthed(session=sess)
        sess.save()

        asset = Asset.objects.create(organization=self.org, name="A1")
        ct = ContentType.objects.get_for_model(Asset)
        a = Attachment.objects.create(
            organization=self.org,
            uploaded_by=self.user,
            file=SimpleUploadedFile("hello.txt", b"hello", content_type="text/plain"),
            filename="hello.txt",
            content_type=ct,
            object_id=str(asset.id),
        )

        r = self.client.post(
            f"/app/files/{a.id}/",
            {"_action": "share_create", "expires_in_hours": "1", "one_time": "1", "label": "Test"},
        )
        self.assertEqual(r.status_code, 302)
        self.assertTrue(AttachmentShareLink.objects.filter(organization=self.org, attachment=a).exists())

        share_url = self.client.session.get(f"file_share_new_url_{self.org.id}_{a.id}", "")
        self.assertIn("/share/f/", share_url)
        share_path = urlsplit(share_url).path

        r = self.client.post(share_path, {"_action": "download"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", (r.headers.get("Content-Disposition") or "").lower())
        body = b"".join(r.streaming_content)
        self.assertEqual(body, b"hello")

        r = self.client.post(share_path, {"_action": "download"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Link consumed", status_code=200)
