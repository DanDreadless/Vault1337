from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0042_file_sha256_unique'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='file',
            options={
                'ordering': ['-created_date'],
                'permissions': [
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
    ]
