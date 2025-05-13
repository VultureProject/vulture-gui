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
__doc__ = 'Job to fetch API Clients log'


from django.conf import settings
from toolkit.api_parser.utils import get_api_parser
from services.frontend.models import Frontend
from system.cluster.models import Cluster
from time import sleep
from multiprocessing import Process
from toolkit.api_parser.api_parser import EarlyTerminationWarning

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


def execute_parser(frontend):
    parser_class = get_api_parser(frontend['api_parser_type'])

    # tenant_name has been introduced later in Vulture-GUI
    # As a result, it may be nonexisting on some vulture instance whose configurations have not been updated
    # So define a 'fake' one to prevent a KeyError
    try:
        frontend['tenant_name']
    except KeyError:
        frontend['tenant_name'] = "PleaseChangeMe"
    try:
        parser = parser_class(frontend)
        if not parser.can_run():
            logger.info("API Parser {} (tenant={}): already running".format(frontend['name'], frontend['tenant_name']),
                        extra={'frontend': str(frontend['name'])})
            return

        logger.info("API Parser {} (tenant={}): starting".format(frontend['name'], frontend['tenant_name']),
                    extra={'frontend': str(frontend['name'])})
        parser.execute()
        try:
            parser.frontend.status[Cluster.get_current_node().name] = "OPEN"
        except Exception as e:
            logger.exception(e)
    except EarlyTerminationWarning as e:
        logger.warning(f"API Parser {frontend['name']} (tenant={frontend['tenant_name']}) stopped early: {e}",
                     extra={'frontend': str(frontend['name'])})
    except Exception as e:
        logger.error(f"API Parser {frontend['name']} (tenant={frontend['tenant_name']}) failure : ",
                     extra={'frontend': str(frontend['name'])})
        logger.exception(e, extra={'frontend': str(frontend['name'])})
        parser.frontend.status[Cluster.get_current_node().name] = "ERROR"
    finally:
        # Delete running key in redis
        logger.info("API Parser {} (tenant={}): ending".format(frontend['name'], frontend['tenant_name']),
                    extra={'frontend': str(frontend['name'])})
        parser.finish()

def node_selected(current_node, frontend):
    """ Small routine that verify if this node has to run the collector """
    if current_node.state == "UP":
        # In any case, actual node has to be up
        if frontend.node == current_node:
            # Return true if the selected node is the current node
            return True
        elif current_node.is_master_mongo:
            # Mongo master will take the ownership if...
            if not frontend.node:
                # ...no specific node selected in the frontend
                return True
            elif frontend.node.state != "UP":
                # ...the selected node is unavailable
                return True
    return False

def api_clients_parser():
    current_node = Cluster.get_current_node()

    api_clients_parser = Frontend.objects.filter(
        mode="log",
        listening_mode="api",
        enabled=True
    )

    processes = []
    for frontend in api_clients_parser:
        if node_selected(current_node, frontend):
            p = Process(target=execute_parser, name=frontend.name, args=(frontend.to_dict(),))
            p.start()
            processes.append(p)

    some_alive = True
    while some_alive:
        finished = []
        some_alive = False

        sleep(1)

        for p in processes:
            p.join(0)
            if p.is_alive():
                some_alive = True
            else:
                finished.append(p)

        processes = list(set(processes) - set(finished))
