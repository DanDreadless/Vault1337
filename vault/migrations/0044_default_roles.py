"""
Data migration: seed the two default roles (Django Groups).

  Staff — all custom vault permissions
  User  — all custom vault permissions except delete_sample and manage_yara

NOTE: Custom permissions are normally created by the post_migrate signal,
which runs after ALL migrations complete. We call create_permissions()
explicitly here so the Permission rows exist when this migration runs.
"""
from django.db import migrations

# Codenames of our custom permissions that are admin-only
_USER_ROLE_EXCLUDED = frozenset({'delete_sample', 'manage_yara'})

# All 13 custom permission codenames declared in File.Meta.permissions
_ALL_CUSTOM = frozenset({
    'upload_sample', 'download_sample', 'delete_sample', 'run_tools',
    'manage_tags', 'manage_iocs', 'enrich_iocs', 'manage_yara',
    'use_intel', 'export_stix', 'vt_enrich', 'mb_lookup', 'add_comments',
})


def create_default_roles(apps, schema_editor):
    from django.contrib.auth.management import create_permissions
    from django.apps import apps as global_apps

    # Ensure vault app's custom Permission rows exist before we query them.
    vault_config = global_apps.get_app_config('vault')
    create_permissions(vault_config, apps=global_apps, verbosity=0)

    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')

    # Only our explicitly declared custom permissions — not Django's
    # auto-generated add_/change_/delete_/view_ permissions.
    all_custom = Permission.objects.filter(
        content_type__app_label='vault',
        codename__in=_ALL_CUSTOM,
    )
    user_custom = all_custom.exclude(codename__in=_USER_ROLE_EXCLUDED)

    staff_group, _ = Group.objects.get_or_create(name='Staff')
    staff_group.permissions.set(all_custom)

    user_group, _ = Group.objects.get_or_create(name='User')
    user_group.permissions.set(user_custom)


def remove_default_roles(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name__in=['Staff', 'User']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0043_file_custom_permissions'),
    ]

    operations = [
        migrations.RunPython(create_default_roles, reverse_code=remove_default_roles),
    ]
