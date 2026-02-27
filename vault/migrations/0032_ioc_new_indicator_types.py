from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0031_file_vt_data'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ioc',
            name='type',
            field=models.CharField(
                choices=[
                    ('ip', 'IP Address'),
                    ('domain', 'Domain'),
                    ('email', 'Email Address'),
                    ('url', 'URL'),
                    ('bitcoin', 'Bitcoin Address'),
                    ('cve', 'CVE Identifier'),
                    ('registry', 'Registry Key'),
                    ('named_pipe', 'Named Pipe / Mutex'),
                ],
                max_length=50,
            ),
        ),
    ]
