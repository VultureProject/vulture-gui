# Generated by Django 4.2.11 on 2025-01-15 16:12

from django.db import migrations, models
import django.utils.timezone
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0076_frontend_cortex_xdr_advanced_token_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_api_key',
            field=models.TextField(default='', help_text='Cisco Umbrella API Key', verbose_name='Cisco Umbrella API Key'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_customers_id',
            field=djongo.models.fields.JSONField(default=[], help_text='Cisco Umbrella customer ids', verbose_name='Cisco Umbrella customer ids'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_customers_tokens',
            field=djongo.models.fields.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_get_dns',
            field=models.BooleanField(default=True, help_text='Get dns logs', verbose_name='Get dns logs'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_get_proxy',
            field=models.BooleanField(default=True, help_text='Get proxy logs', verbose_name='Get proxy logs'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_parent_access_token',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_parent_expires_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='frontend',
            name='cisco_umbrella_managed_org_secret_key',
            field=models.TextField(default='', help_text='Cisco Umbrella secret', verbose_name='Cisco Umbrella secret'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='sentinel_one_singularity_mobile_access_token',
            field=models.TextField(default='', verbose_name='API current cached token'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='sentinel_one_singularity_mobile_access_token_expiry',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='frontend',
            name='sentinel_one_singularity_mobile_client_id',
            field=models.TextField(default='', help_text='Sentinel One Singularity Mobile API client ID', verbose_name='Sentinel One Singularity Mobile API client ID'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='sentinel_one_singularity_mobile_client_secret',
            field=models.TextField(default='', help_text='Sentinel One Singularity Mobile API client secret', verbose_name='Sentinel One Singularity Mobile API client secret'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='sentinel_one_singularity_mobile_host',
            field=models.TextField(default='xxx.mobile.sentinelone.net', help_text='Sentinel One Singularity Mobile API hostname', verbose_name='Sentinel One Singularity Mobile API hostname'),
        ),
    ]
