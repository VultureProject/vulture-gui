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
__doc__ = 'LogRotate service wrapper utils'

# Django system imports
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

# Django project imports
from services.logrotate.models import LogRotateSettings
from services.service import Service

# Local imports
from system.cluster.models import Cluster
from system.config.models import write_conf
from system.exceptions import VultureSystemError
# Required exceptions imports
from services.exceptions import ServiceError, ServiceStatusError, ServiceTestConfigError
from subprocess import CalledProcessError

# Extern modules imports
from subprocess import check_output, PIPE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


LOGROTATE_PATH = "/usr/local/etc/logrotate.d"
LOGROTATE_OWNER = "root:vlt-os"
LOGROTATE_PERMS = "640"

JINJA_PATH = "/home/vlt-os/vulture_os/services/config/"
JINJA_TEMPLATE = "logrotate.conf"


class LogRotateService(Service):
    """ HAProxy service class wrapper """

    def __init__(self):
        super().__init__()
        self.model = LogRotateSettings
        self.service_name = "logrotate"
        self.friendly_name = "Logs rotation"

        self.config_file = JINJA_TEMPLATE
        self.owners = LOGROTATE_OWNER
        self.perms = LOGROTATE_PERMS
        self.jinja_template = {
            'tpl_name': self.config_file,
            'tpl_path': "{}/{}".format(LOGROTATE_PATH, self.config_file),
        }

    def __str__(self):
        return "LogRotate Service"

    # Status inherited from Service class


def reload_conf(node_logger):
    """ Generate and write LogRotate conf file
    :return    A string, what has beeen done
    """
    result = ""

    """ Generate configuration """
    service = LogRotateService()

    if service.reload_conf():
        result += "LogRotate conf updated.\n"
    else:
        result += "LogRotate conf hasn't changed.\n"

    return result
