from django.db.backends.signals import connection_created
from django.db.models.signals import post_delete
from django.dispatch import receiver
from .models import File


@receiver(post_delete, sender=File)
def delete_tags_with_file(sender, instance, **kwargs):
    instance.tag.clear()  # This will remove the association of tags with the file


@receiver(connection_created)
def configure_sqlite(sender, connection, **kwargs):
    """
    Apply performance PRAGMAs on every new SQLite connection.

    WAL allows concurrent readers without blocking writers — a significant
    improvement over the default DELETE journal mode, especially on slow
    filesystems such as bind-mounted Windows paths in Docker on WSL2.
    SYNCHRONOUS=NORMAL is safe with WAL and skips unnecessary fsync calls.
    """
    if connection.vendor == 'sqlite':
        with connection.cursor() as cursor:
            cursor.execute('PRAGMA journal_mode=WAL;')
            cursor.execute('PRAGMA synchronous=NORMAL;')
            cursor.execute('PRAGMA cache_size=-32000;')   # 32 MB page cache
            cursor.execute('PRAGMA temp_store=MEMORY;')  # temp tables in RAM