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


import json
import logging
import os
import subprocess
import sys

from django.conf import settings
from services.frontend.models import Frontend
from system.cluster.models import Cluster

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

MANAGE_PY = os.path.join(settings.BASE_DIR, "manage.py")


def execute_parser(frontend):
    collector = None
    try:
        collector = frontend.api_collector
        if not collector.can_run():
            logger.info("API Collector {} (tenant={}): already running".format(frontend.name, frontend.tenants_config.name),
                        extra={'frontend': str(frontend.name)})
            return

        logger.info("API Collector {} (tenant={}): starting".format(frontend.name, frontend.tenants_config.name),
                    extra={'frontend': str(frontend.name)})
        collector.allow_early_stop()
        collector.execute()
        try:
            collector.frontend.status[Cluster.get_current_node().name] = "OPEN"
        except Exception as e:
            logger.exception(e)
    except Exception as e:
        logger.error(f"API Collector {frontend.name} (tenant={frontend.tenants_config.name}) failure : ",
                     extra={'frontend': str(frontend.name)})
        logger.exception(e, extra={'frontend': str(frontend.name)})
        if collector:
            collector.frontend.status[Cluster.get_current_node().name] = "ERROR"
    # Delete running key in redis - only if not already running (see return above)
    logger.info("API Collector {} (tenant={}): ending".format(frontend.name, frontend.tenants_config.name),
                extra={'frontend': str(frontend.name)})
    if collector:
        collector.finish()

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

def selected_frontend_ids():
    """ Return the ids of the API frontends this node has to collect """
    current_node = Cluster.get_current_node()
    return [
        frontend.pk for frontend in Frontend.objects.filter(
            mode="log",
            listening_mode="api",
            enabled=True
        )
        if node_selected(current_node, frontend)
    ]

def api_clients_parser():
    # The collectors are forked by the run_api_collectors management command, run as a separate
    # manage.py process: this cron process already holds an open MongoClient when the job starts
    # (Django's system checks import forms that query the database), and forking from a process
    # whose monitor threads may be inside OpenSSL can hang the collectors forever.
    # The command is started first so that its Django setup overlaps the selection below.
    spawner = subprocess.Popen([sys.executable, MANAGE_PY, "run_api_collectors", "--stdin"],
                               stdin=subprocess.PIPE)

    frontend_ids = []
    try:
        frontend_ids = selected_frontend_ids()
    finally:
        try:
            spawner.stdin.write(json.dumps(frontend_ids).encode())
            spawner.stdin.close()
        except (OSError, AttributeError) as e:
            logger.error(f"API Collector: could not send frontends to the spawner: {e}", extra={'frontend': 'main'})
        spawner.wait()

    if spawner.returncode != 0:
        logger.critical(f"API Collector: spawner exited with code {spawner.returncode}, "
                        "collectors did not run (see the cron job's stderr)", extra={'frontend': 'main'})
        raise RuntimeError(f"API collector spawner exited with code {spawner.returncode}")
