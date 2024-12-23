# Generated by Django 2.1.3 on 2020-09-18 19:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0018_auto_20200211_1428'),
    ]

    operations = [
        migrations.AddField(
            model_name='frontend',
            name='reachfive_client_id',
            field=models.TextField(default='', help_text='ReachFive client ID', verbose_name='ReachFive client ID for authentication'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='reachfive_client_secret',
            field=models.TextField(default='', help_text='ReachFive client secret', verbose_name='ReachFive client secret for authentication'),
        ),
        migrations.AddField(
            model_name='frontend',
            name='reachfive_host',
            field=models.TextField(default='reachfive.domain.com', help_text='ReachFive host', verbose_name='ReachFive api endpoint domain'),
        )
    ]
