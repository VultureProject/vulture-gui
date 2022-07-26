#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture OS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture OS.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'OpenID Repository model'

# Django system imports
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import ugettext_lazy as _
from django.forms.models import model_to_dict
from django.utils import timezone
from djongo import models

# Django project imports
from authentication.base_repository import BaseRepository
from authentication.user_scope.models import UserScope
from toolkit.auth.authy_client import AuthyClient
from toolkit.auth.vulturemail_client import VultureMailClient
from toolkit.auth.totp_client import TOTPClient
from toolkit.system.hashes import random_sha1
from toolkit.network.network import get_proxy

# Extern modules imports
import requests
from datetime import timedelta
from requests_oauthlib import OAuth2Session

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


CONFIG_RELOAD_INTERVAL = 1 # hour

PROVIDERS_TYPE = (
    ('google', 'Google'),
    ('azure', 'Azure'),
    ('facebook', 'Facebook'),
    ('github', 'Github'),
    ('keycloak', 'Keycloak'),
    ('gitlab', 'Gitlab'),
    ('linkedin', 'Linkedin'),
    ('azureAD', 'Azure AD'),
    ('MazureAD', 'Microsoft Azure AD'),
    ('openid', 'OpenID Connect'),
    ('gov', 'Login.gov'),
    ('nextcloud', 'Nextcloud'),
    ('digitalocean', 'DigitalOcean'),
    ('bitbucket', 'Bitbucket'),
    ('gitea', 'Gitea'),
    ('digital_pass', 'Digital Pass'),
)


class OpenIDRepository(BaseRepository):
    """ Class used to represent an OTP repository object

    api_key: API Key to contact Authy service
    key_length: Temporary key length sent to the user
    otp_type: Type of double authentication
    otp_phone_service: Type of phone service
    otp_mail_service: Type of mail service
    """
    """  """
    provider = models.TextField(
        verbose_name=_('Provider'),
        default=PROVIDERS_TYPE[0][0],
        choices=PROVIDERS_TYPE,
        help_text=_('Type of provider')
    )
    provider_url = models.URLField(
        verbose_name=_("Provider URL"),
        default="https://accounts.google.com",
        help_text=_("Provider URL is the base path to an identity provider's OpenID connect discovery document. \n"
                    "For example, google's URL would be https://accounts.google.com for their discover document.")
    )
    client_id = models.TextField(
        blank=False,
        verbose_name=_("Provider Client ID"),
        help_text=_("Client ID is the OAuth 2.0 Client Identifier retrieved from your identity provider. "
                    "See your identity provider's documentation.")
    )
    client_secret = models.TextField(
        blank=False,
        verbose_name=_("Provider Client Secret"),
        help_text=_("Client secret is the OAuth 2.0 Client secret associated with your client ID and retrieved from your identity provider. "
                    "See your identity provider's documentation.")
    )
    scopes = models.JSONField(
        default=["openid"],
        verbose_name=_("Token scope"),
        help_text=_("Scope to send while requesting token")
    )
    issuer = models.TextField(
        default="",
        verbose_name=_("Issuer to use"),
        help_text=_("")
    )
    authorization_endpoint = models.TextField(
        default="",
        verbose_name=_("Authorization url"),
        help_text=_("")
    )
    token_endpoint = models.TextField(
        default="",
        verbose_name=_("Get token url"),
        help_text=_("")
    )
    userinfo_endpoint = models.TextField(
        default="",
        verbose_name=_("Get user infos url"),
        help_text=_("")
    )
    end_session_endpoint = models.TextField(
        default="",
        verbose_name=_("Disconnect url"),
        help_text=_("")
    )
    last_config_time = models.DateTimeField(
        null=True
    )
    id_alea = models.TextField(
        default=random_sha1
    )
    use_proxy = models.BooleanField(
        default=True,
        verbose_name=_("Use system proxy"),
        help_text=_("Use system proxy (if configured) to contact OpenID provider endpoints")
    )
    verify_certificate = models.BooleanField(
        default=True,
        verbose_name=_("Verify certificate"),
        help_text=_("If the IDP uses auto-signed certificate - disable this option")
    )
    user_scope = models.ForeignKey(
        to=UserScope,
        on_delete=models.PROTECT,
        null=True,
        verbose_name=_("User's scope"),
        help_text=_("Scope of user to construct")
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['provider', 'client_id', 'client_secret'], name="unique_openid_tuple")
        ]


    def __str__(self):
        return "{} ({})".format(self.name, self.str_provider())

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name', 'provider']

    def str_provider(self):
        provider_type = "UNKNOWN"
        for p in PROVIDERS_TYPE:
            if p[0] == self.provider:
                provider_type = p[1]
        return provider_type

    def to_dict(self):
        ret = model_to_dict(self)
        # model_to_dict will not return a list if the field only contains 1 value
        if not isinstance(ret['scopes'], list):
            ret['scopes'] = [ret['scopes']]
        return ret

    def to_template(self):
        """ Returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
            'provider': self.provider,
            'id_alea': self.id_alea
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return {
            'id': str(self.id),
            'name': self.name,
            'provider': self.str_provider(),
            'additional_infos': "URL : {} </br> Callback URL : /oauth2/callback/{}".format(self.provider_url, self.id_alea),
            'callback_url': f"/oauth2/callback/{self.id_alea}"
        }

    # Do NOT forget this on all BaseRepository subclasses
    def save(self, *args, **kwargs):
        self.subtype = "openid"
        super().save(*args, **kwargs)

    def get_client(self):
        if self.otp_phone_service == "authy" and self.otp_type in ["phone", "onetouch"]:
            return AuthyClient(self)
        elif self.otp_type == 'email' and self.otp_mail_service == 'vlt_mail_service':
            return VultureMailClient(self)
        elif self.otp_type == "totp":
            return TOTPClient(self)
        else:
            raise NotImplemented("OTP client type not implemented yet")

    @staticmethod
    def retrieve_config(provider_url, use_proxy=True, verify_certificate=True ):
        logger.info(get_proxy() if use_proxy else None)
        r = requests.get("{}/.well-known/openid-configuration".format(provider_url),
                            proxies=get_proxy() if use_proxy else None,
                            verify=verify_certificate, timeout=10)
        r.raise_for_status()
        config = r.json()
        logger.info(config)
        return config
    
    def openid_save(self, force=True):
        # TODO : Handle CA_BUNDLE
        # If loaded data is too old, reload it again
        refresh_time = timezone.now() - timedelta(hours=CONFIG_RELOAD_INTERVAL)
        if (self.last_config_time is None or self.last_config_time < refresh_time):
            config = OpenIDRepository.retrieve_config(self.provider_url, self.use_proxy, self.verify_certificate)
            self.issuer = config['issuer']
            self.authorization_endpoint = config['authorization_endpoint']
            self.token_endpoint = config['token_endpoint']
            self.userinfo_endpoint = config['userinfo_endpoint']
            self.end_session_endpoint = config.get('end_session_endpoint') or config['revocation_endpoint']
            self.last_config_time = timezone.now()
            self.save()

    def get_oauth2_session(self, redirect_uri):
        session = OAuth2Session(self.client_id, redirect_uri=redirect_uri, scope=self.scopes)
        if self.use_proxy:
            session.proxies=get_proxy()
        if not self.verify_certificate:
            session.verify = False
        return session

    def get_authorization_url(self, oauth2_session):
        """
        :param  redirect_uri parameter in authorization_url
        :return tuple authorization_url, state
        """
        self.openid_save()
        return oauth2_session.authorization_url(self.authorization_endpoint)

    def fetch_token(self, oauth2_session, code):
        self.openid_save()
        return oauth2_session.fetch_token(self.token_endpoint,
                                          code=code,
                                          client_secret=self.client_secret)

    def get_userinfo(self, oauth2_session):
        self.openid_save()
        response = oauth2_session.get(self.userinfo_endpoint, verify=self.verify_certificate)
        response.raise_for_status()
        result = response.json()
        if self.user_scope:
            return self.user_scope.get_user_scope(result, {})
        return result

    @property
    def start_url(self):
        return "oauth2/start?repo={}".format(self.id)
