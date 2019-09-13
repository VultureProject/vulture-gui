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
__doc__ = 'Defender service wrapper utils'

# Django system imports
from django.conf import settings

# Django project imports
from services.service import Service

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


DEFENDER_OWNERS = "vlt-os:vlt-web"
DEFENDER_PERMS = "640"


class DefenderService(Service):
    """ PF service class wrapper """

    def __init__(self):
        super().__init__()
        self.model = None
        self.service_name = "defender"
        self.friendly_name = "Defender"

        self.config_file = ""
        self.owners = DEFENDER_OWNERS
        self.perms = DEFENDER_PERMS
        self.jinja_template = {
            'tpl_name': "",
            'tpl_path': "",
        }

    def __str__(self):
        return "Defender Service"


def restart_service(node_logger):
    """ Method used by vultured API to restart defender service """
    # Do not handle exceptions here, they are handled by process_message
    service = DefenderService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("Defender service restarted : {}".format(result))

    return result
