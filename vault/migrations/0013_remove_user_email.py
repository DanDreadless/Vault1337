# Generated by Django 5.0 on 2023-12-31 10:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0012_user_remove_session_user_delete_customuser_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='email',
        ),
    ]
