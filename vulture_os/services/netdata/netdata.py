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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Netdata service wrapper utils'


from services.netdata.models import NetdataSettings
from toolkit.network.network import get_hostname
from services.service import Service
from system.cluster.models import Cluster, Node
from system.config.models import write_conf
from django.conf import settings

from jinja2 import Environment, FileSystemLoader

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


CONF_PATH = "/usr/local/etc/netdata/"
JINJA_PATH = "/home/vlt-os/vulture_os/services/netdata/config"
NETDATA_OWNER = "root:vlt-web"
NETDATA_PERMS = "640"


class NetdataService(Service):

    """ Netdata services

    Attributes:
        jinja_template (dict): name of template, location on disk
        models (Django model): Related django model
        service_name (str)
    """

    def __init__(self):
        super().__init__()
        self.model = NetdataSettings
        self.service_name = "netdata"
        self.friendly_name = "Netdata"

        self.perms = NETDATA_PERMS
        self.owners = NETDATA_OWNER
        self.jinja_template = {
            'tpl_name': "netdata.conf",
            'tpl_path': '/usr/local/etc/netdata/netdata.conf'
        }

    def __str__(self):
        return "Netdata"


def configure_node(node_logger):
    """ Generate and write netdata conf files """
    node = Cluster.get_current_node()
    nodes = Node.objects.all()

    """ For each Jinja templates """
    jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
    for template_name in jinja2_env.list_templates():
        template = jinja2_env.get_template(template_name)
        conf_path = CONF_PATH
        """ fping.conf has different directory """
        if template_name != "fping.conf":
            """ Other files than fping are in python.d """
            conf_path += "python.d/"

        """ Generate and write the conf depending on all nodes, and current node """
        write_conf(node_logger, [conf_path + template_name,
                                 template.render({'nodes': nodes, 'node': node}),
                                 NETDATA_OWNER, NETDATA_PERMS])


def restart_service(node_logger):
    """ Only way to reload config """
    # Do not handle exceptions here, they are handled by process_message
    service = NetdataService()

    # Warning : can raise ServiceError
    result = service.restart()
    node_logger.info("Netdata service restarted : {}".format(result))
    return result


def reload_conf(node_logger):
    """ Generate and write conf of netdata 
      with NetdataSettings object saved in Mongo 
    Conf differs depending on node, 
      but there is only one NetdataSettings objects for all nodes 
    :param node_logger: Logger sent to all API requests
    :return  Text depending on what has been done
    """
    """ Get node' service object """
    service = NetdataService()

    """ Reload conf if needed (if conf has changed) """
    if service.reload_conf():
        """ If conf has changed, restart service """
        node_logger.debug("Service netdata need to be restarted")
        result = service.restart()
        node_logger.info("Service netdata restarted.")
        return result
    else:
        return "Netdata conf has not changed."
