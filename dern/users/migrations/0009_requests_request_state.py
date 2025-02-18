# Generated by Django 5.1.6 on 2025-02-17 16:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_remove_history_request_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='requests',
            name='request_state',
            field=models.CharField(choices=[('pending', 'Pending'), ('work_on_progress', 'Work On Progress'), ('finished', 'Finished')], default='pending', max_length=20),
        ),
    ]
