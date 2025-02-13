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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Filebeat settings model'

# Django system imports
from django.conf import settings
from djongo import models

# Django project imports
from services.frontend.models import Frontend
from system.config.models import Config
from system.cluster.models import Node
from toolkit.network.network import JAIL_ADDRESSES

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


class FilebeatSettings(models.Model):
    """ Model used to manage global configuration fields of Filebeat """

    def to_template(self):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        """ Variables used by template rendering """
        return {
            'frontends': Frontend.objects.filter(enabled=True, mode="filebeat"),
            'tenants_name': Config.objects.get().internal_tenants.name,
            'nodes': Node.objects.exclude(name=settings.HOSTNAME),
            'jail_addresses': JAIL_ADDRESSES,
        }

    def __str__(self):
        return "Filebeat settings"
