# Generated by Django 5.0 on 2024-04-21 15:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0023_remove_file_tags_tag_files'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='tag',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.DeleteModel(
            name='Tag',
        ),
    ]
