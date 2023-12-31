# Generated by Django 5.0 on 2023-12-31 17:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0014_delete_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tag_name', models.CharField(max_length=200)),
            ],
        ),
        migrations.RemoveField(
            model_name='file',
            name='tag',
        ),
        migrations.AddField(
            model_name='file',
            name='tag',
            field=models.ManyToManyField(blank=True, to='vault.tag'),
        ),
    ]
