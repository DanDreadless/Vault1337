# Generated by Django 4.2.5 on 2023-12-29 12:03

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0006_remove_file_created_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='created_date',
            field=models.DateTimeField(default=datetime.datetime.now),
        ),
    ]
