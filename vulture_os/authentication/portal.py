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

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext as _

# Django project imports

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)


class Portal:

    def __init__(self):
        self.logger = logging.getLogger('gui')

    @property
    def menu(self):
        MENU =  {
            'link': 'portal',
            'icon': 'fas fa-users',
            'text': _('Authentication Portal'),
            #'url': "/portal/user_authentication/"
            'url': "#Coming_Soon",
            'coming_soon': True
        }

        return MENU
