"""
Migration 0045: add view_sample / view_ioc / view_yara permissions.

Schema change: AlterModelOptions registers the new codenames so Django's
post_migrate signal creates the Permission rows.

Data change:
  - Ensures the three Permission rows exist immediately (not waiting for
    post_migrate) by calling create_permissions() explicitly.
  - Adds view_* permissions to every group that already holds at least one
    vault permission (i.e. the Admin / Analyst roles — whatever the operator
    has named them).
  - Creates a "ReadOnly" group with only the three view permissions, for
    users who should browse but not modify anything.
"""
from django.db import migrations

_VIEW_PERMS = frozenset({'view_sample', 'view_ioc', 'view_yara'})


def add_view_permissions(apps, schema_editor):
    from django.contrib.auth.management import create_permissions
    from django.apps import apps as global_apps

    # Ensure all vault Permission rows exist before we query them.
    vault_config = global_apps.get_app_config('vault')
    create_permissions(vault_config, apps=global_apps, verbosity=0)

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')
    ContentType = apps.get_model('contenttypes', 'ContentType')

    # Filter by content_type__model='file' — all custom vault permissions live on
    # the File model.  This excludes Django's auto-generated view_ioc etc. that
    # belong to the IOC / Comment content types.
    view_perms = list(
        Permission.objects.filter(
            content_type__app_label='vault',
            content_type__model='file',
            codename__in=_VIEW_PERMS,
        )
    )

    # Grant view_* to every group that already has at least one vault permission
    # (covers Admin, Analyst, or whatever the operator has named them).
    for group in Group.objects.all():
        if group.permissions.filter(content_type__app_label='vault').exists():
            group.permissions.add(*view_perms)

    # Create the ReadOnly role — view permissions only.
    readonly_group, _ = Group.objects.get_or_create(name='ReadOnly')
    readonly_group.permissions.set(view_perms)


def remove_view_permissions(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    view_perms = Permission.objects.filter(
        content_type__app_label='vault',
        content_type__model='file',
        codename__in=_VIEW_PERMS,
    )

    # Remove view_* from all groups that have them.
    for group in Group.objects.all():
        group.permissions.remove(*view_perms)

    # Remove the ReadOnly group if it only has view permissions (i.e. was
    # created by us and not modified by the operator).
    try:
        readonly = Group.objects.get(name='ReadOnly')
        if not readonly.permissions.exclude(codename__in=_VIEW_PERMS).exists():
            readonly.delete()
    except Group.DoesNotExist:
        pass


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0044_default_roles'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='file',
            options={
                'ordering': ['-created_date'],
                'permissions': [
                    ('view_sample',     'Can view samples'),
                    ('view_ioc',        'Can view IOCs'),
                    ('view_yara',       'Can view YARA rules'),
                    ('upload_sample',   'Can upload samples'),
                    ('download_sample', 'Can download samples'),
                    ('delete_sample',   'Can delete samples'),
                    ('run_tools',       'Can run analysis tools'),
                    ('manage_tags',     'Can add and remove tags'),
                    ('manage_iocs',     'Can manage IOCs'),
                    ('enrich_iocs',     'Can enrich IOCs with external APIs'),
                    ('manage_yara',     'Can manage YARA rules'),
                    ('use_intel',       'Can use IP and domain intelligence'),
                    ('export_stix',     'Can export STIX bundles'),
                    ('vt_enrich',       'Can trigger VirusTotal enrichment'),
                    ('mb_lookup',       'Can trigger MalwareBazaar lookups'),
                    ('add_comments',    'Can add analyst notes and comments'),
                ],
            },
        ),
        migrations.RunPython(add_view_permissions, reverse_code=remove_view_permissions),
    ]
