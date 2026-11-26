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
from services.frontend.models import Frontend
from system.cluster.models import Cluster
from gui.crontab.api_collector_worker import run_collector
from time import sleep
import multiprocessing
import os

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

# Module imported by the forkserver helper process before any collector is forked from it.
FORKSERVER_PRELOAD = "gui.crontab.api_collector_worker"


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

def forkserver_context():
    """ Return a multiprocessing context whose children are forked from a clean helper process.

    Collectors must not be forked from this process: it holds an open MongoClient whose monitor
    threads run TLS handshakes, and a native (OpenSSL/libc) lock held by one of those threads at
    fork() time stays locked forever in the child, which then hangs before doing anything.
    The "forkserver" start method execs a helper process that preloads Django (app registry only,
    no database connection, no thread) and forks every collector from there.
    """
    # Python 3.11's forkserver ignores the sys.path it is handed and silently skips a preload
    # module it cannot import: expose the project to the helper through the environment instead.
    python_path = [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p]
    if settings.BASE_DIR not in python_path:
        os.environ["PYTHONPATH"] = os.pathsep.join([settings.BASE_DIR] + python_path)

    ctx = multiprocessing.get_context("forkserver")
    ctx.set_forkserver_preload([FORKSERVER_PRELOAD])
    return ctx

def api_clients_parser():
    current_node = Cluster.get_current_node()

    frontends = [
        frontend for frontend in Frontend.objects.filter(
            mode="log",
            listening_mode="api",
            enabled=True
        )
        if node_selected(current_node, frontend)
    ]
    if not frontends:
        return

    ctx = forkserver_context()
    processes = []
    for frontend in frontends:
        p = ctx.Process(target=run_collector, name=frontend.name, args=(frontend.pk,))
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
