from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0030_ioc_true_or_false'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='vt_data',
            field=models.JSONField(blank=True, null=True),
        ),
    ]
