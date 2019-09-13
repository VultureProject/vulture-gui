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
__doc__ = 'Openvpn service wrapper utils'

# Django system imports
from django.conf import settings

# Django project imports
from services.service import Service

from subprocess import Popen, PIPE

# Required exceptions import
from services.exceptions import ServiceError, ServiceStatusError

# Extern modules imports
from re import search as re_search

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')

OPENVPN_PERMS = "644"
OPENVPN_OWNERS = "root:wheel"


class OpenvpnService(Service):

    """ Openvpn service class wrapper """
    def __init__(self):
        super().__init__()
        self.service_name = "openvpn_client"
        self.friendly_name = "VPN SSL"


def reload_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = OpenvpnService()

    # Warning : can raise ServiceError
    result = service.reload()
    node_logger.info("Openvpn service reloaded : {}".format(result))
    return result


def restart_service(node_logger):
    """ Only way (for the moment) to reload config """
    # Do not handle exceptions here, they are handled by process_message
    service = OpenvpnService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("Openvpn service restarted : {}".format(result))
    return result


def stop_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = OpenvpnService()

    # Warning : can raise ServiceError
    result = service.stop()
    node_logger.info("Openvpn service stopped : {}".format(result))
    return result


def start_service(node_logger):
    # Do not handle exceptions here, they are handled by process_message
    service = OpenvpnService()

    # Warning : can raise ServiceError
    result = service.start()
    node_logger.info("Openvpn service started : {}".format(result))
    return result


def set_rc_conf(node_logger, yes_no):
    # Do not handle exceptions here, they are handled by process_message
    service = OpenvpnService()
    logger.info(yes_no)
    # Warning : can raise SystemError
    result = service.set_rc_conf(yes_no == "YES")
    node_logger.info("Openvpn enabled set to {}".format(yes_no))
    return result


def reload_conf(node_logger):
    """ Generate and write conf of openvpn
      with OpenvpnSettings object saved in Mongo
    Conf differs depending on node, 
      but there is only one OpenvpnSettings objects for all nodes
    :param node_logger: Logger sent to all API requests
    :return  Text depending on what has been done
    """
    """ Get node' service object """
    service = OpenvpnService()

    """ Reload conf if needed (if conf has changed) """
    if service.reload_conf():
        """ If conf has changed, restart service """
        node_logger.debug("Service openvpn need to be restarted")
        result = service.restart()
        node_logger.info("Service openvpn restarted.")
        return result
    else:
        return "Openvpn conf has not changed."

def get_ssl_tunnels_stats():

    result = {}

    command = ['/sbin/ifconfig', '-l']
    proc = Popen(command, stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        for tun in success.decode('utf8').split(" "):
            tun = tun.rstrip()
            if "tun" not in tun:
                continue

            proc = Popen(['/sbin/ifconfig', tun], stdout=PIPE)
            proc2 = Popen(['/usr/bin/grep', 'inet'], stdin=proc.stdout, stdout=PIPE, stderr=PIPE)
            proc.stdout.close()
            success, error = proc2.communicate()
            if not error:
                result[tun] = success.decode('utf8')
            else:
                result[tun] = error.decode('utf8')

    return result