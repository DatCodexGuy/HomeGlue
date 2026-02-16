from __future__ import annotations

from django.test import TestCase

from apps.core.models import Organization
from apps.workflows.models import WorkflowRule


class WorkflowSeedingTests(TestCase):
    def test_org_create_seeds_default_rules(self):
        org = Organization.objects.create(name="Org A")
        kinds = set(WorkflowRule.objects.filter(organization=org).values_list("kind", flat=True))
        self.assertIn(WorkflowRule.KIND_DOMAIN_EXPIRY, kinds)
        self.assertIn(WorkflowRule.KIND_SSL_EXPIRY, kinds)
        self.assertIn(WorkflowRule.KIND_CHECKLIST_RUN_OVERDUE, kinds)
        self.assertIn(WorkflowRule.KIND_CONFIG_MISSING_PRIMARY_IP, kinds)
        self.assertIn(WorkflowRule.KIND_ASSET_MISSING_LOCATION, kinds)
        self.assertIn(WorkflowRule.KIND_PASSWORD_MISSING_URL, kinds)
        self.assertIn(WorkflowRule.KIND_PASSWORD_ROTATION_DUE, kinds)
        self.assertIn(WorkflowRule.KIND_BACKUP_FAILED_RECENT, kinds)
        self.assertIn(WorkflowRule.KIND_PROXMOX_SYNC_STALE, kinds)
