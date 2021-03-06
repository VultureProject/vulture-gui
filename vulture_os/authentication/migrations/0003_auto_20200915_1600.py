# Generated by Django 2.1.3 on 2020-09-15 16:00

from django.db import migrations, models
import django.db.models.deletion
import djongo.models.fields
import toolkit.system.hashes


class Migration(migrations.Migration):

    dependencies = [
        ('services', '0024_auto_20201228_1710'),
        ('authentication', '0002_delete_accesscontrol'),
    ]

    operations = [
        migrations.CreateModel(
            name='OpenIDRepository',
            fields=[
                ('baserepository_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='authentication.BaseRepository')),
                ('provider', models.TextField(choices=[('google', 'Google'), ('azure', 'Azure'), ('facebook', 'Facebook'), ('github', 'Github'), ('keycloak', 'Keycloak'), ('gitlab', 'Gitlab'), ('linkedin', 'Linkedin'), ('azureAD', 'Azure AD'), ('MazureAD', 'Microsoft Azure AD'), ('openid', 'OpenID Connect'), ('gov', 'Login.gov'), ('nextcloud', 'Nextcloud'), ('digitalocean', 'DigitalOcean'), ('bitbucket', 'Bitbucket'), ('gitea', 'Gitea')], default='google', help_text='Type of provider', verbose_name='Provider')),
                ('provider_url', models.URLField(default='https://accounts.google.com', help_text="Provider URL is the base path to an identity provider's OpenID connect discovery document. \nFor example, google's URL would be https://accounts.google.com for their discover document.", verbose_name='Provider URL')),
                ('client_id', models.TextField(default='', help_text="Client ID is the OAuth 2.0 Client Identifier retrieved from your identity provider. See your identity provider's documentation.", verbose_name='Provider Client ID')),
                ('client_secret', models.TextField(default='', help_text="Client ID is the OAuth 2.0 Client Identifier retrieved from your identity provider. See your identity provider's documentation.", verbose_name='Provider Client Secret')),
                ('issuer', models.TextField(default='', help_text='', verbose_name='Issuer to use')),
                ('authorization_endpoint', models.TextField(default='', help_text='', verbose_name='Authorization url')),
                ('token_endpoint', models.TextField(default='', help_text='', verbose_name='Get token url')),
                ('userinfo_endpoint', models.TextField(default='', help_text='', verbose_name='Get user infos url')),
                ('end_session_endpoint', models.TextField(default='', help_text='', verbose_name='Disconnect url')),
                ('last_config_time', models.DateTimeField(null=True)),
            ],
            bases=('authentication.baserepository',),
        ),
        migrations.RemoveField(
            model_name='userauthentication',
            name='repositories_fallback',
        ),
        migrations.RemoveField(
            model_name='userauthentication',
            name='repository',
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='enable_external',
            field=models.BooleanField(default=False, help_text='Listen portal on dedicated host - required for ', verbose_name='External portal'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='enable_oauth',
            field=models.BooleanField(default=False, help_text='Set portal as OAuth2 provider', verbose_name='Enable OAuth2 provider'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='external_fqdn',
            field=models.CharField(default='auth.testing.tr', help_text='Listening FQDN for external portal', max_length=40, verbose_name='FQDN'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='external_listener',
            field=models.ForeignKey(help_text='Listener used for external portal', null=True, on_delete=django.db.models.deletion.SET_NULL, to='services.Listener', verbose_name='Listen on'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='oauth_client_id',
            field=models.CharField(default=toolkit.system.hashes.random_sha256, help_text='Client_id used to contact OAuth2 provider urls', max_length=64, verbose_name='Application ID (client_id)'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='oauth_client_secret',
            field=models.CharField(default=toolkit.system.hashes.random_sha256, help_text='Client_secret used to contact OAuth2 provider urls', max_length=64, verbose_name='Secret (client_id)'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='oauth_redirect_uris',
            field=djongo.models.fields.JSONField(default=['https://myapp.com/oauth2/callback'], help_text='Use one line per allowed URI', verbose_name=models.CharField()),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='repositories',
            field=djongo.models.fields.ArrayReferenceField(default=[], help_text='Repositories to use to authenticate users (tested in order)', on_delete=django.db.models.deletion.PROTECT, to='authentication.BaseRepository', verbose_name='Authentication repositories'),
        ),
        migrations.AlterField(
            model_name='userauthentication',
            name='otp_repository',
            field=models.ForeignKey(help_text='Double authentication repository to use', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_authentication_otp_set', to='authentication.OTPRepository', verbose_name='OTP Repository'),
        ),
    ]
