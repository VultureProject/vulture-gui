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
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from authentication.base_repository import BaseRepository
from system.cluster.models import Cluster
from toolkit.auth.kerberos_client import KerberosClient

# Extern modules imports

# Required exceptions imports
from system.exceptions import VultureSystemSaveError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class KerberosRepository(BaseRepository):
    """ Class used to represent LDAP repository object
    """
    realm = models.TextField(
        verbose_name=_('Kerberos realm'),
        default="VULTUREPROJECT.ORG",
        help_text=_('Kerberos realm')
    )
    domain_realm = models.TextField(
        verbose_name=_('Kerberos domain realm'),
        default=".vultureproject.org",
        help_text=_('Kerberos domain')
    )
    kdc = models.TextField(
        verbose_name=_('KDC(s)'),
        default="kdc1.vultureproject.org,kdc2.vultureproject.org",
        help_text=_('Kerberos Domain Controler(s).')
    )
    admin_server = models.TextField(
        verbose_name=_('Admin server'),
        default="kdc1.vultureproject.org",
        help_text=_('Administration server host (Typically, the master Kerberos server).')
    )
    krb5_service = models.TextField(
        verbose_name=_('KRB5 Service name'),
        default="vulture.vultureproject.org",
        help_text=_('Kerberos Service Name')
    )
    keytab = models.FileField(
        upload_to="tmp",  # Must be a relative path
        max_length=1000,
        verbose_name=_('Service keytab '),
        help_text=_('Keytab of the service used to contact KDC.')
    )

    def to_dict(self, fields=None):
        return model_to_dict(self, fields=fields)

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
            'realm': self.realm,
            'domain_realm': self.domain_realm,
            'kdc': self.kdc,
            'admin_server': self.admin_server,
            'krb5_service': self.krb5_service
        }

    # Do NOT forget this on all BaseRepository subclasses
    def save(self, *args, **kwargs):
        self.subtype = "KERBEROS"
        super().save(*args, **kwargs)
        self.save_keytab()

    def get_client(self):
        return KerberosClient(self)

    def save_keytab(self):
        """ Write keytab on host to be used
        This function raise VultureSystemConfigError if failure """
        """ API request """
        api_res = Cluster.api_request('toolkit.auth.kerberos_client.write_keytabs')
        if not api_res.get('status'):
            raise VultureSystemSaveError("keytab. API request failure ", traceback=api_res.get('message'))
