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
__doc__ = 'Rsyslog settings model'

# Django system imports
from django.conf import settings
from djongo import models

# Django project imports
from applications.logfwd.models import LogOM
from gui.models.feed import Feed, DATABASES_PATH
from services.frontend.models import Frontend, Listener

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


class RsyslogSettings(models.Model):
    """ Model used to manage global configuration fields of Rsyslogd """

    def to_template(self):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        """ Variables used by template rendering """
        return {
            'frontends': Frontend.objects.filter(enabled=True),
            'max_tcp_listeners': Listener.objects.filter(frontend__enabled=True,
                                                         frontend__listening_mode__icontains="tcp").count() + 1,
            'log_forwarders': LogOM.objects.all(),
            'DATABASES_PATH': DATABASES_PATH
        }

    def __str__(self):
        return "Rsyslogd settings"
