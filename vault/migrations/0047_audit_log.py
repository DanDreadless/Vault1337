from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0046_remove_duplicate_permissions'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('username', models.CharField(blank=True, max_length=150)),
                ('action', models.CharField(
                    choices=[
                        ('login',             'Login'),
                        ('login_failed',      'Login failed'),
                        ('logout',            'Logout'),
                        ('file_upload',       'File upload'),
                        ('file_download',     'File download'),
                        ('file_delete',       'File delete'),
                        ('file_fetch_url',    'File fetched from URL'),
                        ('tag_add',           'Tag added'),
                        ('tag_remove',        'Tag removed'),
                        ('comment_add',       'Comment added'),
                        ('vt_enrich',         'VirusTotal enrichment'),
                        ('mb_lookup',         'MalwareBazaar lookup'),
                        ('stix_export',       'STIX export'),
                        ('ioc_delete',        'IOC deleted'),
                        ('ioc_override',      'IOC verdict overridden'),
                        ('ioc_enrich',        'IOC enriched'),
                        ('yara_create',       'YARA rule created'),
                        ('yara_update',       'YARA rule updated'),
                        ('yara_delete',       'YARA rule deleted'),
                        ('key_change',        'API key changed'),
                        ('user_create',       'User created'),
                        ('user_update',       'User updated'),
                        ('user_delete',       'User deleted'),
                        ('user_set_password', 'User password set'),
                        ('role_create',       'Role created'),
                        ('role_update',       'Role updated'),
                        ('role_delete',       'Role deleted'),
                        ('backup_run',        'Database backup run'),
                        ('cyberchef_update',  'CyberChef updated'),
                    ],
                    db_index=True,
                    max_length=50,
                )),
                ('target_type', models.CharField(blank=True, max_length=50)),
                ('target_id', models.CharField(blank=True, max_length=200)),
                ('detail', models.JSONField(blank=True, null=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='audit_logs',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-timestamp'],
                'indexes': [
                    models.Index(fields=['action'], name='vault_audit_action_idx'),
                    models.Index(fields=['user'], name='vault_audit_user_idx'),
                ],
            },
        ),
    ]
