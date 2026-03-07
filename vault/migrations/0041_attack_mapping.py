from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0040_simhash_signed_field'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='attack_mapping',
            field=models.JSONField(blank=True, null=True),
        ),
    ]
