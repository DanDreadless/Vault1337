"""
Migration 0046: remove custom permissions that duplicate Django auto-generated ones.

The four removed codenames and their replacements:
  view_sample  (file)    → view_file    (file,    Django auto)
  view_ioc     (file)    → view_ioc     (ioc,     Django auto)
  delete_sample(file)    → delete_file  (file,    Django auto)
  add_comments (file)    → add_comment  (comment, Django auto)

For every group that held the old permission the migration:
  1. Adds the equivalent Django auto-generated permission.
  2. Removes the old custom permission.
  3. Deletes the orphaned Permission row.
"""
from django.db import migrations

# Map: old custom codename → (new codename, new content-type model name)
_REPLACEMENTS = {
    'view_sample':  ('view_file',    'file'),
    'view_ioc':     ('view_ioc',     'ioc'),
    'delete_sample': ('delete_file', 'file'),
    'add_comments': ('add_comment',  'comment'),
}


def swap_permissions(apps, schema_editor):
    from django.contrib.auth.management import create_permissions
    from django.apps import apps as global_apps

    # Ensure all auto-generated Permission rows exist before we query them.
    for app_label in ('vault',):
        create_permissions(global_apps.get_app_config(app_label), apps=global_apps, verbosity=0)

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    for old_codename, (new_codename, new_model) in _REPLACEMENTS.items():
        # The old permission lives on the 'file' content type.
        old_perm = Permission.objects.filter(
            content_type__app_label='vault',
            content_type__model='file',
            codename=old_codename,
        ).first()

        # The replacement is an auto-generated permission.
        new_perm = Permission.objects.filter(
            content_type__app_label='vault',
            content_type__model=new_model,
            codename=new_codename,
        ).first()

        if old_perm is None:
            continue  # Already cleaned up or never existed.

        if new_perm is not None:
            # Swap in every group that held the old permission.
            for group in Group.objects.filter(permissions=old_perm):
                group.permissions.add(new_perm)
                group.permissions.remove(old_perm)

        # Delete the now-orphaned custom Permission row.
        old_perm.delete()


def reverse_swap(apps, schema_editor):
    """Best-effort reverse: recreate the old permissions and restore group membership."""
    from django.contrib.auth.management import create_permissions
    from django.apps import apps as global_apps

    vault_config = global_apps.get_app_config('vault')
    create_permissions(vault_config, apps=global_apps, verbosity=0)

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')
    ContentType = apps.get_model('contenttypes', 'ContentType')

    file_ct = ContentType.objects.filter(app_label='vault', model='file').first()
    if file_ct is None:
        return

    _OLD_PERMS = {
        'view_sample':   ('view_file',    'file'),
        'view_ioc':      ('view_ioc',     'ioc'),
        'delete_sample': ('delete_file',  'file'),
        'add_comments':  ('add_comment',  'comment'),
    }
    _OLD_NAMES = {
        'view_sample':   'Can view samples',
        'view_ioc':      'Can view IOCs',
        'delete_sample': 'Can delete samples',
        'add_comments':  'Can add analyst notes and comments',
    }

    for old_codename, (new_codename, new_model) in _OLD_PERMS.items():
        old_perm, _ = Permission.objects.get_or_create(
            content_type=file_ct,
            codename=old_codename,
            defaults={'name': _OLD_NAMES[old_codename]},
        )
        new_perm = Permission.objects.filter(
            content_type__app_label='vault',
            content_type__model=new_model,
            codename=new_codename,
        ).first()
        if new_perm:
            for group in Group.objects.filter(permissions=new_perm):
                group.permissions.add(old_perm)


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0045_view_permissions'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='file',
            options={
                'ordering': ['-created_date'],
                'permissions': [
                    ('view_yara',       'Can view YARA rules'),
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
                ],
            },
        ),
        migrations.RunPython(swap_permissions, reverse_code=reverse_swap),
    ]
