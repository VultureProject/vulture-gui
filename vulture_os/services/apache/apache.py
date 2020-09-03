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
__doc__ = 'Apache GUI service wrapper utils'


# Django system imports
from django.conf import settings

# Django project imports
from services.apache.models import ApacheSettings
from services.service import Service

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


CONF_PATH = "/zroot/apache/usr/local/etc/apache24/"

APACHE_OWNER = "root:vlt-os"
APACHE_PERMS = "640"


class ApacheService(Service):

    """ Apache GUI services

    Attributes:
        jinja_template (dict): name of template, location on disk
        model (Django model): Related django model
        service_name (str)
    """

    def __init__(self):
        super().__init__()
        self.model = ApacheSettings
        self.service_name = "apache24"
        self.friendly_name = "Apache GUI"

        self.owners = APACHE_OWNER
        self.perms = APACHE_PERMS

    def __str__(self):
        return "Apache"


def reload_conf(node_logger):
    """ Generate and write conf of service 
      with ApacheSettings object saved in Mongo 
    Conf differs depending on node, 
      but there is only one ApacheSettings objects for all nodes 
    :param node_logger: Logger sent to all API requests
    :return  Text depending on what has been done
    """
    """ Get node' service object """
    service = ApacheService()

    """ Reload conf if needed (if conf has changed) """
    if service.reload_conf():
        """ If conf has changed, restart service """
        node_logger.debug("Service apache need to be restarted")
        result = service.restart()
        node_logger.info("Service apache restarted.")
        return result
    else:
        return "Apache conf has not changed."


def reload_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = ApacheService()

    # Warning : can raise ServiceError
    result = service.reload()
    node_logger.info("Apache service reloaded : {}".format(result))

    return result


def restart_service(node_logger):
    """ Only way to reload config """
    # Do not handle exceptions here, they are handled by process_message
    service = ApacheService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("Apache service restarted : {}".format(result))
    return result
