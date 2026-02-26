import datetime
from django.db import models
from django.dispatch import receiver
from taggit.managers import TaggableManager
from django.contrib.auth.models import User
from django.db.models.signals import post_save

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
    created_date = models.DateTimeField(default=datetime.datetime.now)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)  # Use SET_NULL if user deletion is allowed
    parent = models.ForeignKey("self", null=True, on_delete=models.CASCADE)
    vt_data = models.JSONField(null=True, blank=True)

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
    ]
    
    type = models.CharField(max_length=50, choices=INDICATOR_TYPES)
    value = models.CharField(max_length=500, unique=True)
    files = models.ManyToManyField(File, related_name='iocs')
    true_or_false = models.BooleanField(default=True)
    description = models.TextField(blank=True, null=True)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.type}: {self.value}"

class Comment(models.Model):
    title = models.CharField(max_length=200)
    text = models.CharField(max_length=200)
    file = models.ForeignKey(File, on_delete=models.CASCADE)

    def __str__(self):
        return self.title

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    job_role = models.CharField(max_length=200, blank=True)
    department = models.CharField(max_length=200, blank=True)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)

    def __str__(self):
        return self.user.username
    

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    instance.profile.save()
