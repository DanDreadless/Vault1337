# Generated by Django 5.0 on 2023-12-30 18:35

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0009_alter_file_options'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=200)),
                ('email', models.CharField(max_length=200)),
                ('password', models.CharField(max_length=200)),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vault.file')),
            ],
        ),
        migrations.AlterField(
            model_name='session',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vault.customuser'),
        ),
        migrations.DeleteModel(
            name='User',
        ),
    ]
