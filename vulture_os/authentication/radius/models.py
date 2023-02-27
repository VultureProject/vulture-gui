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
__doc__ = 'RADIUS Repository model'

# Django system imports
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from authentication.base_repository import BaseRepository
from toolkit.auth.radius_client import RadiusClient

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class RadiusRepository(BaseRepository):
    """ Class used to represent RADIUS repository object

    radius_host: IP Address used to contact RADIUS server
    radius_port: Port used to contact RADIUS server
    radius_nas_id: NAS_ID of RADIUS server
    radius_secret: Secret used to authenticate client
    """

    # Connection related attributes
    host = models.TextField(
        null=False,
        verbose_name=_('Host'),
        help_text=_('IP Address of RADIUS server')
    )
    port = models.PositiveIntegerField(
        verbose_name=_('Port'),
        default=1812,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text=_('Listening authentication port of RADIUS server')
    )
    nas_id = models.TextField(
        verbose_name=_('NAS_ID'),
        default="0",
        help_text=_('NAS_ID of the RADIUS server')
    )
    secret = models.TextField(
        verbose_name=_("Authentication secret"),
        help_text=_('Secret used to authenticate clients')
    )
    retry = models.PositiveIntegerField(
        verbose_name=_("Max retries to authenticate clients"),
        default=3,
        help_text=_('Max number of retries to contact Radius server')
    )
    timeout = models.PositiveIntegerField(
        verbose_name=_("Max timeout to authenticate clients"),
        default=2,
        help_text=_('Max timeout to contact Radius server')
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
            'uri': "{}:{}".format(self.host, self.port),
            'nas_id': self.nas_id,
            'retry': self.retry,
            'timeout': self.timeout
        }

    # Do NOT forget this on all BaseRepository subclasses
    def save(self, *args, **kwargs):
        self.subtype = "RADIUS"
        super().save(*args, **kwargs)

    def get_client(self):
        return RadiusClient(self)
