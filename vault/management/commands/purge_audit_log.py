from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from vault.models import AuditLog, FailedLoginAttempt


class Command(BaseCommand):
    help = "Delete AuditLog records older than AUDIT_LOG_RETENTION_DAYS and stale FailedLoginAttempt records."

    def handle(self, *args, **options):
        retention_days = getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 365)
        cutoff = timezone.now() - timedelta(days=retention_days)
        deleted_audit, _ = AuditLog.objects.filter(timestamp__lt=cutoff).delete()
        self.stdout.write(
            f"Purged {deleted_audit} audit log record(s) older than {retention_days} days."
        )

        # Also clean up FailedLoginAttempt records older than the lockout window (no longer actionable).
        attempt_cutoff = timezone.now() - timedelta(minutes=15)
        deleted_attempts, _ = FailedLoginAttempt.objects.filter(timestamp__lt=attempt_cutoff).delete()
        self.stdout.write(f"Purged {deleted_attempts} expired failed login attempt record(s).")
