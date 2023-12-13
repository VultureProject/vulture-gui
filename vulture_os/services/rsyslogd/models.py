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
from django.db.models import Q

# Django project imports
from applications.logfwd.models import LogOM
from applications.reputation_ctx.models import ReputationContext, DATABASES_PATH
from services.frontend.models import Frontend, Listener
from system.cluster.models import Cluster
from system.config.models import Config

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
        current_node = Cluster.get_current_node()
        frontends = set(listener.frontend for listener in Listener.objects.filter(network_address__nic__node=current_node).distinct())
        frontends.update(Frontend.objects.filter(
            Q(mode="log", listening_mode__in=['redis', 'kafka', 'file'], node=current_node) |
            Q(mode="log", listening_mode__in=['redis', 'kafka', 'file'], node=None) |
            Q(mode="filebeat", filebeat_listening_mode__in=["file", "api"], node=current_node) |
            Q(mode="log", listening_mode="api")).distinct())
        return {
            'frontends': frontends,
            'node': current_node,
            'max_tcp_listeners': Listener.objects.filter(frontend__listening_mode__icontains="tcp",frontend__enabled=True).count() + Frontend.objects.filter(enabled=True, listening_mode="api").count() + 1,
            'log_forwarders': LogOM.objects.all(),
            'DATABASES_PATH': DATABASES_PATH,
            'tenants_name': Config.objects.get().internal_tenants.name
        }

    def __str__(self):
        return "Rsyslogd settings"
