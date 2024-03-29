# Generated by Django 3.0.5 on 2022-12-05 15:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0048_auto_20220913_1643'),
    ]

    operations = [
        migrations.DeleteModel(
            name='ApacheSettings',
        ),
        migrations.AddField(
            model_name='frontend',
            name='proofpoint_casb_api_key',
            field=models.TextField(default='', help_text='Proofpoint CASB API KEY'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='proofpoint_casb_client_id',
            field=models.TextField(default='', help_text='Proofpoint CASB Client ID'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='proofpoint_casb_client_secret',
            field=models.TextField(default='', help_text='Proofpoint CASB Client Secret'),
        ),
    ]
