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
__doc__ = 'LDAP Repository model'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from applications.portal_template.models import portalTemplate
from authentication.base_repository import BaseRepository
from authentication.otp.models import OTPRepository

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


AUTH_TYPE_CHOICES = (
    ('form', 'HTML Form'),
    ('basic', 'Basic Authentication'),
    ('kerberos', 'Kerberos Authentication')
)

SSO_TYPE_CHOICES = (
    ('form', 'HTML Form'),
    ('basic', 'Basic Authentication'),
    ('kerberos', 'Kerberos Authentication')
)
SSO_BASIC_MODE_CHOICES = (
    ('autologon', 'using AutoLogon'),
    ('learning', 'using SSO Learning'),
)
SSO_CONTENT_TYPE_CHOICES = (
    ('default', 'application/x-www-form-urlencoded'),
    ('multipart', 'multipart/form-data'),
    ('json', 'application/json')
)


#    enable_oauth2 = models.BooleanField(
#         default=False,
#         verbose_name=_("Enable OAuth2"),
#         help_text=_("If checked, OAuth2 authentication is allowed")
#     )
#     enable_stateless_oauth2 = models.BooleanField(
#         default=False,
#         verbose_name=_("Enable stateless OAuth2"),
#         help_text=_("If checked, Vulture will accept OAuth2 HTTP header as a login")
#     )

class UserAuthentication(models.Model):
    """ Class used to represent a Portal instance used for authentication

    """
    """ Mandatory principal attributes """
    name = models.TextField(
        default="Users authentication",
        unique=True,
        verbose_name=_("Name"),
        help_text=_("Custom object name")
    )
    enable_tracking = models.BooleanField(
        default=True,
        verbose_name=_("Track anonymous connections"),
        help_text=_("If disable, Vulture won\'t give a cookie to anonymous users")
    )
    repository = models.ForeignKey(
        BaseRepository,
        verbose_name=_('Authentication repository'),
        help_text=_("Repository to use to authenticate users"),
        on_delete=models.PROTECT,
        related_name="user_authentication_set",
    )
    repositories_fallback = models.ArrayReferenceField(
        BaseRepository,
        default=[],
        on_delete=models.SET_DEFAULT,
        verbose_name=_("Authentication fallback repositories"),
        help_text=_("Repositories to use to authenticate users if main repository failed."),
        related_name="user_authentication_fallback_set",
    )
    auth_type = models.TextField(
        default=AUTH_TYPE_CHOICES[0][0],
        choices=AUTH_TYPE_CHOICES,
        verbose_name=_("Authentication type"),
        help_text=_("Type of authentication to ask from client")
    )
    portal_template = models.ForeignKey(
        portalTemplate,
        null=True,
        on_delete=models.PROTECT,
        verbose_name=_("Portal template"),
        help_text=_('Select the template to use for user authentication portal')
    )
    auth_timeout = models.PositiveIntegerField(
        default=900,
        verbose_name=_("Disconnection timeout"),
        help_text=_("Expiration timeout of portal cookie")
    )
    enable_timeout_restart = models.BooleanField(
        default=True,
        verbose_name=_("Reset timeout after a request"),
        help_text=_("Restart timeout after a request")
    )
    enable_captcha = models.BooleanField(
        default=False,
        verbose_name=_("Enable captcha"),
        help_text=_("Ask a captcha validation")
    )
    otp_repository = models.ForeignKey(
        to=OTPRepository,
        null=True,
        on_delete=models.SET_NULL,
        verbose_name=_("OTP Repository"),
        help_text=_("Double authentication repository to use")
    )
    otp_max_retry = models.PositiveIntegerField(
        default=3,
        verbose_name=_("Retries numbers"),
        help_text=_("Maximum number of OTP retries until deauthentication")
    )
    disconnect_url = models.TextField(
        default="/disconnect",
        verbose_name=_("Disconnect regex"),
        help_text=_("Regex for the application disconnect page (ex: 'logout\?sessid=.*'")
    )
    enable_disconnect_message = models.BooleanField(
        default=False,
        verbose_name=_("Display the disconnect message from template"),
        help_text=_("Display the disconnect template message instead of redirecting user.")
    )
    enable_disconnect_portal = models.BooleanField(
        default=False,
        verbose_name=_("Destroy portal session on disconnect"),
        help_text=_("Also disconnect the user from the portal.")
    )
    enable_registration = models.BooleanField(
        default=False,
        verbose_name=_("Enable users registration by mail"),
        help_text=_("Enable users registration")
    )
    group_registration = models.TextField(
        default="",
        verbose_name=_("Add users in group (ldap)"),
        help_text=_("Group of ldap registered users")
    )
    update_group_registration = models.BooleanField(
        default=False,
        verbose_name=_("Update group members (ldap)"),
        help_text=_("Update group members")
    )

    def __str__(self):
        return "{} ({})".format(self.name, str(self.repository))

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name', 'repository']

    def str_auth_type(self):
        auth_type = "UNKNOWN"
        for auth in AUTH_TYPE_CHOICES:
            if auth[0] == self.auth_type:
                auth_type = auth[1]
        return auth_type

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        result = {
            'id': str(self.id),
            'name': self.name,
            'enable_tracking': self.enable_tracking,
            'repositories': [str(self.repository)],
            'enable_captcha': self.enable_captcha,
            'otp_repository': str(self.otp_repository) if self.otp_repository else "",
            'enable_registration': self.enable_registration,
            'auth_type': self.str_auth_type()
        }
        for repo in self.repositories_fallback.all():
            result['repositories'].append(str(repo))
        return result
