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
__doc__ = 'PF settings model'

# Django system imports
from django.conf import settings
from djongo import models

# Django project imports
from applications.reputation_ctx.models import DATABASES_PATH
from system.cluster.models import Cluster, Node, NetworkInterfaceCard
from toolkit.network.network import JAIL_ADDRESSES
from toolkit.network.network import get_sanitized_proxy

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')

# Proxy configuration imports


class PFSettings(models.Model):
    """ Model used to manage global configuration fields of PF 
    Particularity is that config attributes are in Node and Config object,
    so only need Config here, because Node is sent everytime in template rendering
    """

    def to_template(self):
        """ Dictionary used to create configuration file
        :return     Dictionnary of configuration parameters
        """
        node = Cluster.get_current_node()

        return {
            'nodes': Node.objects.exclude(name=settings.HOSTNAME),
            'carp_allowed_interfaces': set(NetworkInterfaceCard.objects.filter(
                networkaddress__carp_vhid__gt=0,
                node__name=settings.HOSTNAME).values_list('dev', flat=True)),
            'global_config': Cluster.get_global_config(),
            'jail_addresses': JAIL_ADDRESSES,
            'databases_path': DATABASES_PATH,
            'proxy': get_sanitized_proxy(),
            'listeners_enabled': node.get_listeners_enabled,
            'forwarders_enabled': node.get_forwarders_enabled,
            'backends_enabled': node.get_backends_enabled
        }

    def __str__(self):
        return "PF settings"
