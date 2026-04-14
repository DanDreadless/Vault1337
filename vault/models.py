from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from taggit.managers import TaggableManager


def _validate_profile_image_size(image):
    limit = 2 * 1024 * 1024  # 2 MB
    if image.size > limit:
        raise ValidationError("Profile image must be 2 MB or smaller.")

# Create your models here.
class File(models.Model):
    name = models.CharField(max_length=200)
    size = models.IntegerField()
    magic = models.CharField(max_length=200)
    mime = models.CharField(max_length=200)
    md5 = models.CharField(max_length=200)
    sha1 = models.CharField(max_length=200)
    sha256 = models.CharField(max_length=200, unique=True)
    sha512 = models.CharField(max_length=200)
    tag = TaggableManager(blank=True)
    created_date = models.DateTimeField(default=timezone.now)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)  # Use SET_NULL if user deletion is allowed
    parent = models.ForeignKey("self", null=True, on_delete=models.CASCADE)
    vt_data = models.JSONField(null=True, blank=True)
    mb_data = models.JSONField(null=True, blank=True)
    simhash = models.BigIntegerField(null=True, blank=True)
    simhash_input_size = models.IntegerField(null=True, blank=True)
    attack_mapping = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['-created_date']
        permissions = [
            # ---- Read access ----
            # view_file   → Django auto-generated (use that, not a duplicate here)
            # view_ioc    → Django auto-generated on IOC model
            # add_comment → Django auto-generated on Comment model
            # delete_file → Django auto-generated on File model
            ('view_yara',       'Can view YARA rules'),
            # ---- Write / action permissions ----
            ('upload_sample',   'Can upload samples'),
            ('download_sample', 'Can download samples'),
            ('run_tools',       'Can run analysis tools'),
            ('manage_tags',     'Can add and remove tags'),
            ('manage_iocs',     'Can manage IOCs'),
            ('enrich_iocs',     'Can enrich IOCs with external APIs'),
            ('manage_yara',     'Can manage YARA rules'),
            ('use_intel',       'Can use IP and domain intelligence'),
            ('export_stix',     'Can export STIX bundles'),
            ('vt_enrich',       'Can trigger VirusTotal enrichment'),
            ('mb_lookup',       'Can trigger MalwareBazaar lookups'),
        ]

class IOC(models.Model):
    INDICATOR_TYPES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('email', 'Email Address'),
        ('url', 'URL'),
        ('bitcoin', 'Bitcoin Address'),
        ('cve', 'CVE Identifier'),
        ('registry', 'Registry Key'),
        ('named_pipe', 'Named Pipe / Mutex'),
        ('win_persistence', 'Windows Persistence (Run/Services)'),
        ('scheduled_task', 'Scheduled Task'),
        ('linux_cron', 'Linux Cron Persistence'),
        ('systemd_unit', 'Systemd Unit Persistence'),
        ('macos_launchagent', 'macOS LaunchAgent / LaunchDaemon'),
    ]
    
    type = models.CharField(max_length=50, choices=INDICATOR_TYPES)
    value = models.CharField(max_length=500, unique=True)
    files = models.ManyToManyField(File, related_name='iocs')
    true_or_false = models.BooleanField(default=True)
    manually_overridden = models.BooleanField(default=False)
    enriched = models.JSONField(null=True, blank=True)
    enriched_at = models.DateTimeField(null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.type}: {self.value}"

class AnalysisResult(models.Model):
    """Persisted output from a workbench tool run."""

    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='analysis_results')
    tool = models.CharField(max_length=50)
    sub_tool = models.CharField(max_length=50, blank=True, default='')
    output = models.TextField()
    ran_at = models.DateTimeField(auto_now_add=True)
    ran_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-ran_at']
        indexes = [
            models.Index(fields=['file', 'tool', 'sub_tool']),
        ]

    def __str__(self):
        label = f"{self.tool}/{self.sub_tool}" if self.sub_tool else self.tool
        return f"{label} @ {self.file.sha256[:8]}"


class Comment(models.Model):
    COMMENT_TYPES = [
        ('note',        'Note'),
        ('hypothesis',  'Hypothesis'),
        ('ioc_context', 'IOC Context'),
        ('verdict',     'Verdict'),
    ]

    title = models.CharField(max_length=200)
    text = models.CharField(max_length=4000)
    comment_type = models.CharField(max_length=20, choices=COMMENT_TYPES, default='note')
    file = models.ForeignKey(File, on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_date = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['created_date']

    def __str__(self):
        return self.title

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    job_role = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=200, blank=True)
    profile_image = models.ImageField(
        upload_to='profile_images/', null=True, blank=True,
        validators=[_validate_profile_image_size],
    )

    def __str__(self):
        return self.user.username
    

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    instance.profile.save()


class AuditLog(models.Model):
    ACTION_CHOICES = [
        # Auth
        ('login',                  'Login'),
        ('login_failed',           'Login failed'),
        ('logout',                 'Logout'),
        ('password_reset_request', 'Password reset requested'),
        ('password_reset_confirm', 'Password reset confirmed'),
        # Files
        ('file_upload',       'File upload'),
        ('file_download',     'File download'),
        ('file_delete',       'File delete'),
        ('file_fetch_url',    'File fetched from URL'),
        # Tags / comments
        ('tag_add',           'Tag added'),
        ('tag_remove',        'Tag removed'),
        ('comment_add',       'Comment added'),
        # Enrichment
        ('vt_enrich',         'VirusTotal enrichment'),
        ('mb_lookup',         'MalwareBazaar lookup'),
        ('stix_export',       'STIX export'),
        # IOCs
        ('ioc_delete',        'IOC deleted'),
        ('ioc_override',      'IOC verdict overridden'),
        ('ioc_enrich',        'IOC enriched'),
        # YARA
        ('yara_create',       'YARA rule created'),
        ('yara_update',       'YARA rule updated'),
        ('yara_delete',       'YARA rule deleted'),
        # Admin — keys, users, roles
        ('account_lockout',   'Account locked out'),
        ('account_unlock',    'Account unlocked by admin'),
        ('key_change',        'API key changed'),
        ('user_create',       'User created'),
        ('user_update',       'User updated'),
        ('user_delete',       'User deleted'),
        ('user_set_password', 'User password set'),
        ('role_create',       'Role created'),
        ('role_update',       'Role updated'),
        ('role_delete',       'Role deleted'),
        # System
        ('backup_run',        'Database backup run'),
        ('cyberchef_update',  'CyberChef updated'),
    ]

    timestamp   = models.DateTimeField(auto_now_add=True, db_index=True)
    user        = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='audit_logs',
    )
    # Denormalised snapshot — preserved even if the user is later deleted.
    username    = models.CharField(max_length=150, blank=True)
    action      = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)
    target_type = models.CharField(max_length=50, blank=True)   # 'file', 'user', 'ioc', …
    target_id   = models.CharField(max_length=200, blank=True)  # sha256, username, rule name, …
    detail      = models.JSONField(null=True, blank=True)        # extra structured context
    ip_address  = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action']),
            models.Index(fields=['user']),
        ]

    def __str__(self):
        who = self.username or '(system)'
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} {who} {self.action} {self.target_id}"


class FailedLoginAttempt(models.Model):
    """One row per failed login. Used to enforce account lockout."""
    username   = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp  = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['username', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.timestamp:%Y-%m-%d %H:%M:%S} failed login: {self.username}"
