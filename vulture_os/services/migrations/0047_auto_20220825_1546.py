# Generated by Django 3.0.5 on 2022-08-25 15:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0046_auto_20220818_1153'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='ratelimit_burst',
            field=models.PositiveIntegerField(blank=True, help_text='Specifies the rate-limiting burst in number of messages.', null=True),
        ),
        migrations.AddField(
            model_name='frontend',
            name='ratelimit_interval',
            field=models.PositiveIntegerField(blank=True, help_text='Specifies the rate-interval in seconds. 0 means no rate-limiting.', null=True),
        ),
        migrations.AddField(
            model_name='frontend',
            name='symantec_token',
            field=models.TextField(default='none', help_text='Symantec Token'),
        ),
    ]
