from __future__ import annotations

from datetime import date, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.core.models import Organization, OrganizationMembership
from apps.assets.models import ConfigurationItem
from apps.checklists.models import ChecklistRun
from apps.netapp.models import Domain
from apps.workflows.engine import run_rule
from apps.workflows.models import Notification, WorkflowRule, WorkflowRuleRun
from apps.secretsapp.models import PasswordEntry


class WorkflowEngineTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="u1", password="pw")
        self.user2 = User.objects.create_user(username="u2", password="pw")
        self.org = Organization.objects.create(name="Org 1")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=OrganizationMembership.ROLE_ADMIN)
        OrganizationMembership.objects.create(user=self.user2, organization=self.org, role=OrganizationMembership.ROLE_MEMBER)

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
        self.assertEqual(WorkflowRuleRun.objects.filter(organization=self.org, rule=rule).count(), 1)

    def test_password_rules_do_not_notify_users_without_password_access(self):
        # Password is admins-only (default) and created by admin user.
        p = PasswordEntry.objects.create(organization=self.org, name="Secret", created_by=self.user, visibility=PasswordEntry.VIS_ADMINS, url="")
        rule = WorkflowRule.objects.create(
            organization=self.org,
            name="Password missing URL",
            kind=WorkflowRule.KIND_PASSWORD_MISSING_URL,
            enabled=True,
            params={},
            run_interval_minutes=60,
            audience=WorkflowRule.AUDIENCE_ALL,  # would normally notify everyone
        )
        res = run_rule(rule)
        self.assertTrue(res.ok)
        # Admin gets it, member does not.
        self.assertTrue(Notification.objects.filter(organization=self.org, user=self.user, object_id=str(p.id)).exists())
        self.assertFalse(Notification.objects.filter(organization=self.org, user=self.user2, object_id=str(p.id)).exists())

    def test_backup_failed_recent_creates_notification(self):
        from apps.backups.models import BackupSnapshot
        from django.utils import timezone

        b = BackupSnapshot.objects.create(organization=self.org, status=BackupSnapshot.STATUS_FAILED, error="boom")
        rule = WorkflowRule.objects.create(
            organization=self.org,
            name="Backup failures",
            kind=WorkflowRule.KIND_BACKUP_FAILED_RECENT,
            enabled=True,
            params={"days": 30},
            run_interval_minutes=60,
            audience=WorkflowRule.AUDIENCE_ADMINS,
        )
        res = run_rule(rule)
        self.assertTrue(res.ok)
        self.assertTrue(Notification.objects.filter(organization=self.org, user=self.user, object_id=str(b.id)).exists())

    def test_proxmox_sync_stale_creates_notification(self):
        from apps.integrations.models import ProxmoxConnection
        from django.utils import timezone

        c = ProxmoxConnection.objects.create(
            organization=self.org,
            name="PVE",
            base_url="https://pve.example.com:8006",
            token_id="root@pam!t",
            enabled=True,
            sync_interval_minutes=15,
            last_sync_at=timezone.now() - timezone.timedelta(hours=10),
            last_sync_ok=False,
            last_sync_error="timeout",
        )
        rule = WorkflowRule.objects.create(
            organization=self.org,
            name="Proxmox stale",
            kind=WorkflowRule.KIND_PROXMOX_SYNC_STALE,
            enabled=True,
            params={"stale_minutes": 60},
            run_interval_minutes=60,
            audience=WorkflowRule.AUDIENCE_ADMINS,
        )
        res = run_rule(rule)
        self.assertTrue(res.ok)
        self.assertTrue(Notification.objects.filter(organization=self.org, user=self.user, object_id=str(c.id)).exists())

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
