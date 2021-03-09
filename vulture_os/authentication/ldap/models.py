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
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import ugettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from authentication.base_repository import BaseRepository
from toolkit.auth.ldap_client import LDAPClient

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

LDAP_PROTO_CHOICES = (
    (3, 'LDAP v3'),  # v3 by default (v2 not secure)
    (2, 'LDAP v2'),
)
LDAP_ENC_SCHEMES_CHOICES = (
    ('none', 'None (usual port: 389)'),
    ('ldaps', 'LDAPS (usual port: 636)'),
    ('start-tls', 'Start-TLS (usual port: 389)'),
)
LDAP_SCOPES_CHOICES = (
    (0, 'base (the suffix entry only)'),
    (1, 'one (one level under suffix)'),
    (2, 'subtree (all levels under suffix)'),
)
OAUTH2_TYPE_CHOICES = (
    ('dict', 'Dictionnary of keys and values'),
    ('list', 'List of values')
)
OAUTH2_TOKEN_CHOICES = (
    ('header', 'Header'),
    ('json', 'JSON'),
    ('both', 'Header and JSON')
)


class LDAPRepository(BaseRepository):
    """ Class used to represent LDAP repository object

    ldap_host: IP Address used to contact LDAP server
    ldap_port: Port used to contact LDAP server
    ldap_protocol: LDAP protocol version
    ldap_encryption_scheme: Encryption scheme used by LDAP Server
    ldap_connection_dn: DN of LDAP service account
    ldap_password: password of LDAP service account
    ldap_base_dn: Base DN of LDAP filter
    ldap_user_scope: User LDAP search scope
    ldap_user_dn: User DN of LDAP filter (concatenated with Base DN)
    ldap_user_attr: Attribute which identify user (ex: SamAccountName)
    ldap_user_filter: User search filter
    ldap_user_account_locked_attr: Filter which permit to identify a locked
    account
    ldap_user_change_password_attr: Filter which permit to identify an expired
    password
    ldap_user_groups_attr: LDAP Attribute with list of group membership
    ldap_user_mobile_attr: LDAP attribute with user phone number
    ldap_user_email_attr: LDAP attribute with user email address
    ldap_group_scope: Group LDAP search scope
    ldap_group_dn: Group DN of LDAP filter (concatenated with Base DN)
    ldap_group_attr: Attribute which identify group
    ldap_group_filter: Group search filter
    ldap_group_member_attr: LDAP Attribute with list of users
    """
    """ * Connection related attributes * """
    host = models.TextField(
        verbose_name=_('Host'),
        help_text=_('IP Address of LDAP server')
    )
    port = models.PositiveIntegerField(
        verbose_name=_('Port'),
        default=389,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text=_('Listening port of LDAP server')
    )
    protocol = models.PositiveIntegerField(
        verbose_name=_('Protocol'),
        default=LDAP_SCOPES_CHOICES[0][0],
        choices=LDAP_PROTO_CHOICES,
        help_text=_('Version of your LDAP protocol')
    )
    encryption_scheme = models.TextField(
        verbose_name=_("Encryption scheme"),
        default=LDAP_ENC_SCHEMES_CHOICES[0][0],
        choices=LDAP_ENC_SCHEMES_CHOICES,
        help_text=_('LDAP encryption scheme')
    )
    connection_dn = models.TextField(
        verbose_name=_("Service account DN"),
        help_text=_('DN used by Vulture to perform LDAP query')
    )
    dn_password = models.TextField(
        verbose_name=_("Service account password"),
        help_text=_('Password of service account')
    )
    base_dn = models.TextField(
        verbose_name=_("Base DN"),
        help_text=_('Location in the directory from  which the LDAP search begins')
    )
    """ * User search related attributes * """
    user_scope = models.PositiveIntegerField(
        verbose_name=_("User search scope"),
        default=LDAP_SCOPES_CHOICES[0][0],
        choices=LDAP_SCOPES_CHOICES,
        help_text=_('Deep of search operation')
    )
    user_dn = models.TextField(
        verbose_name=_("User DN"),
        help_text=_('Location in the directory from which the user LDAP search begins')
    )
    user_attr = models.TextField(
        verbose_name=_("User attribute"),
        default="uid",
        help_text=_('Attribute which identify user')
    )
    user_filter = models.TextField(
        verbose_name=_("User search filter"),
        default='(objectclass=person)',
        help_text=_('Filter used to found user. Ex: (objectClass=person)')
    )
    user_account_locked_attr = models.TextField(
        verbose_name=_("Account locked filter"),
        help_text=_('Filter used to identify if an  account is locked.  Ex: (lockoutTime>=1)')
    )
    user_change_password_attr = models.TextField(
        verbose_name=_("Need change password  filter"),
        help_text=_('Filter used to identify if an  account need to change its password. Ex:  (pwdLastSet=0)')
    )
    user_groups_attr = models.TextField(
        verbose_name=_("Group attribute"),
        help_text=_("Attribute which contains user's group list")
    )
    user_mobile_attr = models.TextField(
        verbose_name=_("Mobile attribute"),
        help_text=_("Attribute which contains user's mobile number")
    )
    user_email_attr = models.TextField(
        verbose_name=_("Email attribute"),
        help_text=_("Attribute which contains user's email address")
    )

    user_smartcardid_attr = models.TextField(
        verbose_name=_("Smart Card ID attribute"),
        default="",
        help_text=_("Attribute which contains user's SmartCard ID")
    )
    """ * Group search related attributes * """
    group_scope = models.PositiveIntegerField(
        verbose_name=_("Group search scope"),
        default=LDAP_SCOPES_CHOICES[0][0],
        choices=LDAP_SCOPES_CHOICES,
        help_text=_('Deep of search operation')
    )
    group_dn = models.TextField(
        verbose_name=_("Group DN"),
        help_text=_('Location in the directory from which the group LDAP search begins')
    )
    group_attr = models.TextField(
        default="cn",
        verbose_name=_("Group attribute"),
        help_text=_("Attribute which identify group")
    )
    group_filter = models.TextField(
        verbose_name=_("Group search filter"),
        default="(objectClass=groupOfNames)",
        help_text=_('Filter used to found group. Ex: (objectClass=group)')
    )
    group_member_attr = models.TextField(
        verbose_name=_("Members attribute"),
        default="member",
        help_text=_("Attribute which contains  list of group members")
    )

    def create_user_dn(self, user_name):
        return f"{self.user_attr}={user_name},{self.user_dn},{self.base_dn}"

    def create_group_dn(self, group_name):
        return f"{self.group_attr}={group_name},{self.group_dn},{self.base_dn}"

    def to_dict(self):
        return model_to_dict(self)

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return {
            'id': str(self.id),
            'name': self.name,
            'uri': "{}://{}:{}".format(self.encryption_scheme, self.host, self.port),
            'connection_dn': self.connection_dn,
            'base_dn': self.base_dn
        }

    # Do NOT forget this on all BaseRepository subclasses
    def save(self, *args, **kwargs):
        self.subtype = "LDAP"
        super().save(*args, **kwargs)

    def get_client(self):
        return LDAPClient(self)
