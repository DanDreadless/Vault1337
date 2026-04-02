from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0041_attack_mapping'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='sha256',
            field=models.CharField(max_length=200, unique=True),
        ),
    ]
