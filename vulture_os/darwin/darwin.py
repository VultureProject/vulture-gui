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
__doc__ = 'Darwin main models'


from django.utils.translation import gettext as _
from django.conf import settings

from services.darwin.darwin import DarwinService

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)


class Darwin:

    def __init__(self):
        self.logger = logging.getLogger('gui')

    @property
    def menu(self):
        MENU = {
            'link': 'darwin',
            'icon': 'fas fa-atom',
            'text': _('Security engine'),
            'url': "#",
            'submenu': [
                {
                    'link': 'access_control',
                    'text': _('Access Control'),
                    'url': '/darwin/acl/'
                },
                {
                    'link': 'policy',
                    'text': _('Darwin Engine'),
                    'url': '/darwin/policy/',
                    'state': DarwinService().last_status()[0]
                }
            ]
        }

        return MENU
