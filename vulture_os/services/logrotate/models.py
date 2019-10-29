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
__doc__ = 'Haproxy settings model'

# Django system imports
from django.conf import settings
from django.db.models import Q
from djongo import models

# Django project imports
from applications.logfwd.models import LogOMFile
from system.cluster.models import Cluster

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


class LogRotateSettings(models.Model):
    """ Model used to manage configuration of LogRotate """

    def to_template(self):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        # Get all files used by enabled frontends in log_forwarders or log_forwarders_parse_failure
        # FIXME : It seems to have a bug in QuerySet, the merge of 2 querysets does not work
        # So, waiting for correction, use 2 queries and a list .....
        log_oms = list(LogOMFile.objects.filter(frontend_set__enabled=True))
        log_oms = set(log_oms + list(LogOMFile.objects.filter(frontend_failure_set__enabled=True)))
        """ First, use to_mongo() internal django function """
        return {
            'log_forwarders': log_oms
        }

    def __str__(self):
        return "LogRotate settings"

