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
__doc__ = 'LogForwarder main models'


from django.utils.translation import ugettext as _
from django.conf import settings

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)


class Apps:

    def __init__(self):
        self.logger = logging.getLogger('gui')

    @property
    def menu(self):
        MENU = {
            'link': 'applications',
            'icon': 'fa fa-server',
            'text': _('Applications'),
            'url': "#",
            'submenu': [
                {
                    'link': 'backend',
                    'text': 'Applications',
                    'url': '/apps/backend/',
                    'state': "DOWN"
                },
                {
                    'link': 'logfwd',
                    'text': 'Logs Forwarder',
                    'url': '/apps/logfwd/',
                    'state': "DOWN"
                },
                {
                    'link': 'reputation_ctx',
                    'text': 'Context Tags',
                    'url': '/apps/reputation_ctx/',
                    'state': "DOWN"
                },
                {
                    'link': 'parser',
                    'text': 'Parsers',
                    'url': '/apps/parser/',
                    'state': "DOWN"
                }
            ]
        }

        return MENU
