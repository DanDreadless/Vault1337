# Generated by Django 4.2.5 on 2023-12-29 11:57

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0005_alter_file_created_date'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='file',
            name='created_date',
        ),
    ]
