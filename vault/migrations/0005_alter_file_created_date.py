# Generated by Django 4.2.5 on 2023-12-29 11:55

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0004_alter_file_created_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime.now),
        ),
    ]
