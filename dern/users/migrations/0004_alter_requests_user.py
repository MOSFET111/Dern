# Generated by Django 5.1.6 on 2025-02-15 23:35

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_requests_email_requests_phone'),
    ]

    operations = [
        migrations.AlterField(
            model_name='requests',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user_requests', to=settings.AUTH_USER_MODEL),
        ),
    ]
