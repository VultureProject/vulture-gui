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
__doc__ = 'Strongswan service wrapper utils'

# Django system imports
from django.conf import settings

# Django project imports
from services.service import Service

# Required exceptions import
from services.exceptions import ServiceStatusError

# Extern modules imports
from re import search as re_search

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')

STRONGSWAN_PERMS = "644"
STRONGSWAN_OWNERS = "root:wheel"


class StrongswanService(Service):

    """ Strongswan service class wrapper """
    def __init__(self):
        super().__init__("strongswan")
        self.friendly_name = "IPSEC"

    def statusall(self):
        stdout, stderr, code = self._exec_cmd("onestatusall")

        """ Strongswan return status of configuration """
        if stderr and code != 0:
            # Entry missing in /usr/local/etc/sudoers.d/vulture_sudoers
            if "sudo: no tty present and no askpass program specified" in stderr:
                raise ServiceStatusError("User vlt-os don't have permissions to do \"service strongswan onestatusall\"."
                                         "Check sudoers file.", "strongswan", traceback=" ")
        elif code == 1 and not stdout and not stderr:
            """ If no error, code=0 and no stdout => service stopped """
            return ""
        elif stdout:
            """ Stdout contains the status of the tunnels """
            return stdout

        """ If we get here : there was an error """
        raise ServiceStatusError("No referenced error", "strongswan", traceback=stderr)

    def __str__(self):
        return "Strongswan Service"


def reload_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = StrongswanService()

    # Warning : can raise ServiceError
    result = service.reload()
    node_logger.info("Strongswan service reloaded : {}".format(result))
    return result


def restart_service(node_logger):
    """ Only way (for the moment) to reload config """
    # Do not handle exceptions here, they are handled by process_message
    service = StrongswanService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("Strongswan service restarted : {}".format(result))
    return result


def stop_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = StrongswanService()

    # Warning : can raise ServiceError
    result = service.stop()
    node_logger.info("Strongswan service stopped : {}".format(result))
    return result


def start_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = StrongswanService()

    # Warning : can raise ServiceError
    result = service.start()
    node_logger.info("Strongswan service started : {}".format(result))
    return result


def set_rc_conf(node_logger, yes_no):
    # Do not handle exceptions here, they are handled by process_message
    service = StrongswanService()
    logger.info(yes_no)
    # Warning : can raise SystemError
    result = service.set_rc_conf(yes_no == "YES")
    node_logger.info("Strongswan enabled set to {}".format(yes_no))
    return result


def get_ipsec_tunnels_stats():
    service = StrongswanService()

    # Warning, can raise ServiceError
    result = service.statusall()

    tunnel_stats = {}
    sa_showed = False
    cpt = 0
    nb_up = 0
    nb_connecting = 0
    for line in result.split('\n'):
        if cpt > 0:
            match = re_search("(vlan_\d+\{\d+\}):\s+(\S+)\s+===\s+(\S+)", line)
            if not match and cpt == 2:
                logger.error("STRONGSWAN :: get_tunnel_stats: The following line not recognized: {}".format(line))
            elif not match and cpt == 1:
                cpt += 1
            elif match:
                tunnel_stats[match.group(3)] = ["UP", match.group(1)]
                cpt = 0
        elif not sa_showed:
            match = re_search("Security Associations \((\d+) up, (\d+) connecting\):", line)
            if match:
                nb_up = match.group(1)
                nb_connecting = match.group(2)
                logger.info("STRONGSWAN :: get_tunnel_stats: Tunnels {} up, {} connecting.".format(nb_up, nb_connecting))
                sa_showed = True
        else:
            match = re_search(" +vlan_(\d+\{\d+\}): +INSTALLED, ", line)
            if match:
                logger.debug("STRONGSWAN :: get_tunnel_stats: Tunnel up: {}".format(match.group(1)))
                cpt = 1

    return result, tunnel_stats, nb_up, nb_connecting


def reload_conf(node_logger):
    """ Generate and write conf of strongswan 
      with StrongswanSettings object saved in Mongo 
    Conf differs depending on node, 
      but there is only one StrongswanSettings objects for all nodes 
    :param node_logger: Logger sent to all API requests
    :return  Text depending on what has been done
    """
    """ Get node' service object """
    service = StrongswanService()

    """ Reload conf if needed (if conf has changed) """
    if service.reload_conf():
        """ If conf has changed, restart service """
        node_logger.debug("Service stronswan need to be restarted")
        result = service.restart()
        node_logger.info("Service stronswan restarted.")
        return result
    else:
        return "Strongswan conf has not changed."
