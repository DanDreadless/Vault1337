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
    sha256 = models.CharField(max_length=200)
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
