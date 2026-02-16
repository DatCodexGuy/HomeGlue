from __future__ import annotations

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.core.models import Organization, OrganizationMembership
from apps.assets.models import ConfigurationItem
from apps.checklists.models import ChecklistRun
from apps.netapp.models import Domain
from apps.workflows.engine import run_rule
from apps.workflows.models import Notification, WorkflowRule


class WorkflowEngineTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)

    def test_domain_expiry_creates_deduped_notifications(self):
        d = Domain.objects.create(organization=self.org, name="example.com", expires_on=date.today() + timedelta(days=10))
        rule = WorkflowRule.objects.create(
            organization=self.org,
            name="Domain expiry",
            kind=WorkflowRule.KIND_DOMAIN_EXPIRY,
            enabled=True,
            params={"days": 30},
            run_interval_minutes=60,
            audience=WorkflowRule.AUDIENCE_ADMINS,
        )

        res1 = run_rule(rule)
        self.assertTrue(res1.ok)
        self.assertEqual(Notification.objects.filter(organization=self.org, user=self.user).count(), 1)

    def test_checklist_run_overdue_creates_notifications(self):
        run = ChecklistRun.objects.create(
            organization=self.org,
            name="Weekly review",
            status=ChecklistRun.STATUS_OPEN,
            due_on=date.today() - timedelta(days=2),
        )
        rule = WorkflowRule.objects.create(
            organization=self.org,
            name="Overdue",
            kind=WorkflowRule.KIND_CHECKLIST_RUN_OVERDUE,
            enabled=True,
            params={"grace_days": 0},
            run_interval_minutes=60,
            audience=WorkflowRule.AUDIENCE_ADMINS,
        )
        res = run_rule(rule)
        self.assertTrue(res.ok)
        self.assertTrue(
            Notification.objects.filter(organization=self.org, user=self.user, content_type__model="checklistrun", object_id=str(run.id)).exists()
        )

    def test_config_missing_primary_ip_creates_notifications(self):
        ci = ConfigurationItem.objects.create(organization=self.org, name="srv1", primary_ip="")
        rule = WorkflowRule.objects.create(
            organization=self.org,
            name="Missing IP",
            kind=WorkflowRule.KIND_CONFIG_MISSING_PRIMARY_IP,
            enabled=True,
            params={},
            run_interval_minutes=60,
            audience=WorkflowRule.AUDIENCE_ADMINS,
        )
        res = run_rule(rule)
        self.assertTrue(res.ok)
        self.assertTrue(
            Notification.objects.filter(
                organization=self.org, user=self.user, content_type__model="configurationitem", object_id=str(ci.id)
            ).exists()
        )

        # Run again should not create duplicates (dedupe_key includes expires_on).
        res2 = run_rule(rule)
        self.assertTrue(res2.ok)
        self.assertEqual(Notification.objects.filter(organization=self.org, user=self.user).count(), 1)
