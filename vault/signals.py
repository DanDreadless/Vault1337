from django.db.models.signals import post_delete
from django.dispatch import receiver
from .models import File

@receiver(post_delete, sender=File)
def delete_tags_with_file(sender, instance, **kwargs):
    instance.tag.clear()  # This will remove the association of tags with the file