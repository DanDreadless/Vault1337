# Generated by Django 5.0 on 2024-04-21 14:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0017_file_tag'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='file',
            name='tag',
        ),
        migrations.AddField(
            model_name='file',
            name='tags',
            field=models.CharField(default='te', max_length=200),
            preserve_default=False,
        ),
    ]
