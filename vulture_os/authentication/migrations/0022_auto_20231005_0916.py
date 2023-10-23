# Generated by Django 3.2.20 on 2023-10-13 16:11

import bson.objectid
from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0021_auto_20230830_0807'),
    ]

    operations = [
        migrations.AddField(
            model_name='openidrepository',
            name='enable_jwt',
            field=models.BooleanField(blank=True, default=False, help_text='JWT used to authenticate/authorize user', verbose_name='Authorize JWT'),
        ),
        migrations.AddField(
            model_name='openidrepository',
            name='jwt_key',
            field=models.TextField(blank=True, default='', help_text="Secret/pubkey used to validate jwt's signature", verbose_name='Key'),
        ),
        migrations.AddField(
            model_name='openidrepository',
            name='jwt_signature_type',
            field=models.TextField(blank=True, choices=[('HS256', 'hmac using sha265'), ('HS384', 'hmac using sha384'), ('HS512', 'hmac using sha512'), ('RS256', 'rsa_pkcs1 using sha256'), ('RS384', 'rsa_pkcs1 using sha384'), ('RS512', 'rsa_pkcs1 using sha512'), ('ES256', 'ecdsa using p256 & sha256'), ('ES384', 'ecdsa using p384 & sha384'), ('ES512', 'ecdsa using p512 & sha512'), ('PS256', 'rsa_pss using mgf1 & sha256'), ('PS384', 'rsa_pss using mgf1 & sha384'), ('PS512', 'rsa_pss using mgf1 & sha512')], default='HS256', help_text='Signature type as given in RFC7518', verbose_name='Signature type'),
        ),
        migrations.AddField(
            model_name='openidrepository',
            name='jwt_validate_audience',
            field=models.BooleanField(blank=True, default=True, help_text="Be more flexible without verifying who's the token for, used when multiple fqdn need to be reached (default=on)", verbose_name='Validate audience'),
        ),
    ]
