# Generated by Django 5.0 on 2024-04-21 15:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0021_rename_tags_tag_name'),
    ]

    operations = [
        migrations.RenameField(
            model_name='tag',
            old_name='name',
            new_name='tags',
        ),
    ]