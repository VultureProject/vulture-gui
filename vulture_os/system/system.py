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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Services main models'


from django.utils.translation import ugettext as _
from django.conf import settings

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)

logger = logging.getLogger('system')


class System:

    def __init__(self):
        self.logger = logging.getLogger('system')

    @property
    def menu(self):
        MENU = {
            'link': 'system',
            'icon': 'fa fa-microchip',
            'text': _('System'),
            'url': "#",
            'submenu': [{
                'link': 'config',
                'text': 'Cluster config',
                'url': '/system/config'
            }, {
                'link': 'cluster',
                'text': 'Nodes Config',
                'url': '/system/cluster'
            }, {
                'link': 'netif',
                'text': 'Network Interfaces',
                'url': '/system/netif'
            }, {
                'link': 'users',
                'text': 'Users',
                'url': '/system/users'
            }, {
                'link': 'vm',
                'text': 'Virtual Machines',
                'url': '/system/vm'
            }, {
                'link': 'pki',
                'text': 'X509 Certificates',
                'url': '/system/pki'
            }, {
                'link': 'tls_profile',
                'text': 'TLS Profiles',
                'url': '/system/tls_profile'
            }, {
                'link': 'zfs',
                'text': 'ZFS Filesystem',
                'url': '/system/zfs'
            }, {
                'link': 'error_templates',
                'text': 'HTTP Messages',
                'url': '/system/template/',
            }

            ]
        }

        return MENU
