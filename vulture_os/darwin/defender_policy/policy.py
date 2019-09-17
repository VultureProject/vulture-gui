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
__doc__ = 'Haproxy service wrapper utils'

# Django system imports
from django.conf import settings

# Local imports
from darwin.defender_policy.models import DefenderPolicy, DEFENDER_PATH
from system.config.models import delete_conf as delete_conf_file
from services.defender.defender import restart_service

# Required exceptions imports
from system.exceptions import VultureSystemError

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


HAPROXY_PATH = "/usr/local/etc/haproxy.d"
TEST_CONF_PATH = "/var/tmp/haproxy"

HAPROXY_OWNER = "vlt-os:vlt-web"
HAPROXY_PERMS = "644"


def write_defender_conf(node_logger, policy_id):
    """ Generate and write Defender conf file, depending on policy conf
    :return    A string, what has been done
    """
    policy = DefenderPolicy.objects.get(pk=policy_id)

    # If we need to restart the service, we do it locally
    if policy.write_defender_conf():
        restart_service(logger)

        return "Defender conf updated"

    return "Defender conf not updated"


def write_defender_spoe_conf(node_logger, policy_id):
    """ Generate and write Defender conf file, depending on policy conf
    :return    A string, what has been done
    """
    policy = DefenderPolicy.objects.get(pk=policy_id)

    if policy.write_spoe_conf():
        return "Defender SPOE conf updated"

    return "Defender SPOE conf not updated"


def write_defender_backend_conf(node_logger, policy_id):
    """ Generate and write Defender conf file, depending on policy conf
    :return    A string, what has been done
    """
    policy = DefenderPolicy.objects.get(pk=policy_id)

    if policy.write_backend_conf():
        return "Defender backend conf updated"

    return "Defender backend conf not updated"


def delete_defender_conf(node_logger, policy_id):
    defender_conf_filename = "{}/defender_{}.conf".format(DEFENDER_PATH, policy_id)
    spoe_conf_filename = "{}/spoe_defender_{}.txt".format(HAPROXY_PATH, policy_id)
    backend_conf_filename = "{}/backend_defender_{}.cfg".format(HAPROXY_PATH, policy_id)

    try:
        delete_conf_file(node_logger, defender_conf_filename)
    except VultureSystemError as error:
        if "No such file or directory" in str(error):
            node_logger.info("File {} already deleted".format(defender_conf_filename))
        else:
            raise

    try:
        delete_conf_file(node_logger, spoe_conf_filename)
    except VultureSystemError as error:
        if "No such file or directory" in str(error):
            node_logger.info("File {} already deleted".format(spoe_conf_filename))
        else:
            raise

    try:
        delete_conf_file(node_logger, backend_conf_filename)
    except VultureSystemError as error:
        if "No such file or directory" in str(error):
            node_logger.info("File {} already deleted".format(backend_conf_filename))
        else:
            raise

    restart_service(node_logger)

    return "Defender configuration files successfully updated"
