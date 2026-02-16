from __future__ import annotations

from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.assets.models import Asset, ConfigurationItem
from apps.core.models import (
    CustomField,
    CustomFieldValue,
    Location,
    Organization,
    OrganizationMembership,
    Relationship,
    RelationshipType,
    Tag,
    UserProfile,
)
from apps.docsapp.models import Document, DocumentTemplate
from apps.people.models import Contact
from apps.secretsapp.models import PasswordEntry


@dataclass(frozen=True)
class Ref:
    ct: ContentType
    obj_id: str


class Command(BaseCommand):
    help = "Seed a small set of demo orgs/items/relationships for manual testing."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="demo")
        parser.add_argument("--password", default="demo123!")
        parser.add_argument("--reset", action="store_true", help="Delete existing demo orgs before seeding.")
        parser.add_argument("--force-password", action="store_true", help="Reset the demo user's password.")

    def _ref(self, obj) -> Ref:
        ct = ContentType.objects.get_for_model(obj.__class__)
        return Ref(ct=ct, obj_id=str(obj.pk))

    def _rel_get_or_create(self, *, org: Organization, rt: RelationshipType, source: Ref, target: Ref, user):
        """
        Mirror Relationship.save() canonicalization for symmetric types so get_or_create
        doesn't miss an existing row and then fail on unique constraints.
        """
        if rt.symmetric:
            s_key = (int(source.ct.pk), str(source.obj_id))
            t_key = (int(target.ct.pk), str(target.obj_id))
            if s_key > t_key:
                source, target = target, source

        return Relationship.objects.get_or_create(
            organization=org,
            relationship_type=rt,
            source_content_type=source.ct,
            source_object_id=source.obj_id,
            target_content_type=target.ct,
            target_object_id=target.obj_id,
            defaults={"created_by": user},
        )

    def handle(self, *args, **opts):
        username: str = opts["username"]
        password: str = opts["password"]
        reset: bool = bool(opts["reset"])
        force_password: bool = bool(opts["force_password"])

        User = get_user_model()

        with transaction.atomic():
            if reset:
                Organization.objects.filter(name__in=["Acme", "Globex"]).delete()

            user, created = User.objects.get_or_create(
                username=username,
                defaults={"is_staff": True, "is_active": True},
            )
            if created or force_password:
                user.set_password(password)
                user.save(update_fields=["password"])

            org_acme, _ = Organization.objects.get_or_create(name="Acme", defaults={"description": "Demo org: Acme"})
            org_globex, _ = Organization.objects.get_or_create(name="Globex", defaults={"description": "Demo org: Globex"})

            OrganizationMembership.objects.get_or_create(
                organization=org_acme, user=user, defaults={"role": OrganizationMembership.ROLE_OWNER}
            )
            OrganizationMembership.objects.get_or_create(
                organization=org_globex, user=user, defaults={"role": OrganizationMembership.ROLE_ADMIN}
            )

            profile, _ = UserProfile.objects.get_or_create(user=user)
            if not profile.default_organization_id:
                profile.default_organization = org_acme
                profile.save(update_fields=["default_organization"])

            # Tags (global + org-scoped)
            tag_prod, _ = Tag.objects.get_or_create(organization=None, name="Production")
            tag_staging, _ = Tag.objects.get_or_create(organization=None, name="Staging")
            tag_vip_acme, _ = Tag.objects.get_or_create(organization=org_acme, name="VIP")
            tag_network_acme, _ = Tag.objects.get_or_create(organization=org_acme, name="Network")

            # Locations
            hq, _ = Location.objects.get_or_create(organization=org_acme, name="HQ", defaults={"address": "123 Main St"})
            dc, _ = Location.objects.get_or_create(organization=org_acme, name="Datacenter", defaults={"address": "DC Row 7"})

            # Contacts
            alice, _ = Contact.objects.get_or_create(
                organization=org_acme,
                first_name="Alice",
                last_name="Admin",
                defaults={"email": "alice@example.com", "title": "IT Admin"},
            )
            alice.tags.set([tag_vip_acme, tag_prod])

            # Assets / CIs
            fw, _ = Asset.objects.get_or_create(
                organization=org_acme,
                name="Firewall-01",
                defaults={"asset_type": Asset.TYPE_NETWORK, "manufacturer": "Netgate", "model": "6100", "location": dc},
            )
            fw.tags.set([tag_network_acme, tag_prod])

            esxi, _ = Asset.objects.get_or_create(
                organization=org_acme,
                name="ESXi-01",
                defaults={"asset_type": Asset.TYPE_SERVER, "manufacturer": "Dell", "model": "R740", "location": dc},
            )
            esxi.tags.set([tag_prod])

            laptop, _ = Asset.objects.get_or_create(
                organization=org_acme,
                name="Alice-Laptop",
                defaults={"asset_type": Asset.TYPE_LAPTOP, "manufacturer": "Lenovo", "model": "T14", "location": hq},
            )
            laptop.tags.set([tag_staging])

            vm01, _ = ConfigurationItem.objects.get_or_create(
                organization=org_acme,
                name="VM01",
                defaults={"ci_type": ConfigurationItem.TYPE_VM, "hostname": "vm01.acme.local", "notes": "Demo VM"},
            )
            vm01.tags.set([tag_prod])

            # Docs / Templates
            tpl, _ = DocumentTemplate.objects.get_or_create(
                organization=org_acme,
                name="Runbook",
                defaults={"body": "## Purpose\n\n## Steps\n\n- Step 1\n- Step 2\n"},
            )
            tpl.tags.set([tag_prod])

            doc_vpn, _ = Document.objects.get_or_create(
                organization=org_acme,
                title="VPN Setup",
                defaults={"body": "VPN setup notes (demo).", "template": tpl},
            )
            if doc_vpn.template_id != tpl.id:
                doc_vpn.template = tpl
                doc_vpn.save(update_fields=["template"])
            doc_vpn.tags.set([tag_network_acme, tag_prod])

            # Passwords
            pw, _ = PasswordEntry.objects.get_or_create(
                organization=org_acme,
                name="Firewall Admin",
                defaults={"username": "admin", "url": "https://firewall-01/"},
            )
            if not pw.password_ciphertext:
                pw.set_password("ChangeMe-Now!")
                pw.save(update_fields=["password_ciphertext"])
            pw.tags.set([tag_network_acme, tag_prod])

            # Relationship types
            rt_runs_on, _ = RelationshipType.objects.get_or_create(
                organization=org_acme,
                name="Runs On",
                defaults={"inverse_name": "Hosts", "symmetric": False},
            )
            rt_connected, _ = RelationshipType.objects.get_or_create(
                organization=org_acme,
                name="Connected To",
                defaults={"inverse_name": "", "symmetric": True},
            )
            rt_documented, _ = RelationshipType.objects.get_or_create(
                organization=org_acme,
                name="Documented By",
                defaults={"inverse_name": "Documents", "symmetric": False},
            )

            # Relationships (exercise generic linking + symmetric canonical ordering)
            r_vm01 = self._ref(vm01)
            r_esxi = self._ref(esxi)
            r_fw = self._ref(fw)
            r_doc_vpn = self._ref(doc_vpn)

            self._rel_get_or_create(org=org_acme, rt=rt_runs_on, source=r_vm01, target=r_esxi, user=user)
            self._rel_get_or_create(org=org_acme, rt=rt_documented, source=r_fw, target=r_doc_vpn, user=user)

            # Symmetric: try both directions, ensure only one row exists.
            self._rel_get_or_create(org=org_acme, rt=rt_connected, source=r_fw, target=r_esxi, user=user)
            self._rel_get_or_create(org=org_acme, rt=rt_connected, source=r_esxi, target=r_fw, user=user)

            # Custom fields + values (exercise ContentType scoping)
            ct_asset = ContentType.objects.get_for_model(Asset)
            cf_warranty, _ = CustomField.objects.get_or_create(
                organization=org_acme,
                content_type=ct_asset,
                key="warranty_expires",
                defaults={
                    "name": "Warranty Expires",
                    "field_type": CustomField.TYPE_DATE,
                    "help_text": "YYYY-MM-DD",
                    "sort_order": 10,
                },
            )
            cf_is_critical, _ = CustomField.objects.get_or_create(
                organization=org_acme,
                content_type=ct_asset,
                key="critical",
                defaults={
                    "name": "Critical",
                    "field_type": CustomField.TYPE_BOOLEAN,
                    "help_text": "Treat as critical infrastructure.",
                    "sort_order": 20,
                },
            )
            # Values for ESXi host
            CustomFieldValue.objects.update_or_create(
                organization=org_acme,
                field=cf_warranty,
                content_type=ct_asset,
                object_id=str(esxi.id),
                defaults={"value_text": "2027-01-31"},
            )
            CustomFieldValue.objects.update_or_create(
                organization=org_acme,
                field=cf_is_critical,
                content_type=ct_asset,
                object_id=str(esxi.id),
                defaults={"value_text": "1"},
            )

        self.stdout.write(self.style.SUCCESS("Seed complete."))
        self.stdout.write(f"User: {username} (password: {'(set)' if created or force_password else '(unchanged)'})")
        self.stdout.write(f"Orgs: {Organization.objects.filter(name__in=['Acme','Globex']).count()}")
        self.stdout.write(f"Acme assets: {Asset.objects.filter(organization__name='Acme').count()}")
        self.stdout.write(f"Acme docs: {Document.objects.filter(organization__name='Acme').count()}")
        self.stdout.write(f"Acme relationships: {Relationship.objects.filter(organization__name='Acme').count()}")
