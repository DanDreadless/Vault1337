# Generated by Django 5.0 on 2024-04-21 15:01

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0020_rename_name_tag_tags'),
    ]

    operations = [
        migrations.RenameField(
            model_name='tag',
            old_name='tags',
            new_name='name',
        ),
    ]