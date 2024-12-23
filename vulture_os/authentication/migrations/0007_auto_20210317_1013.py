# Generated by Django 3.0.5 on 2021-03-17 10:13

from django.db import migrations, models
import toolkit.system.hashes


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0006_auto_20210323_1030'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userauthentication',
            name='oauth_client_secret',
            field=models.CharField(default=toolkit.system.hashes.random_sha256, help_text='Client_secret used to contact OAuth2 provider urls', max_length=64, verbose_name='Secret (client_secret)'),
        ),
        migrations.AddField(
            model_name='openidrepository',
            name='use_proxy',
            field=models.BooleanField(default=True,
                                      help_text='Use system proxy (if configured) to contact OpenID provider endpoints',
                                      verbose_name='Use system proxy'),
        ),
        migrations.AddField(
            model_name='openidrepository',
            name='verify_certificate',
            field=models.BooleanField(default=True,
                                      help_text='If the IDP uses auto-signed certificate - disable this option',
                                      verbose_name='Verify certificate'),
        )
    ]
