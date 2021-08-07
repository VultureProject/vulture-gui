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
from multiprocessing import Process

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


def execute_parser(frontend):
    parser_class = get_api_parser(frontend['api_parser_type'])

    # tenant_name has been introduced later in Vulture-GUI
    # As a result, it may be nonexisting on some vulture instance whose configurations have not been updated
    # So define a 'fake' one to prevent a KeyError
    try:
        frontend['tenant_name']
    except KeyError:
        frontend['tenant_name'] = "PleaseChangeMe"

    parser = parser_class(frontend)
    if not parser.can_run():
        logger.info("API Parser {} (tenant={}): already running".format(frontend['name'], frontend['tenant_name']))
        return
    try:
        logger.info("API Parser {} (tenant={}): starting".format(frontend['name'], frontend['tenant_name']))
        parser.execute()
    except Exception as e:
        logger.error(f"API Parser {frontend['name']} (tenant={frontend['tenant_name']}) failure : ")
        logger.exception(e)
    finally:
        # Delete running key in redis
        logger.info("API Parser {} (tenant={}): ending".format(frontend['name'], frontend['tenant_name']))
        parser.finish()


def api_clients_parser():
    current_node = Cluster.get_current_node()
    if not current_node.is_master_mongo:
        return

    api_clients_parser = Frontend.objects.filter(
        mode="log",
        listening_mode="api",
        enabled=True
    )

    processes = []
    for frontend in api_clients_parser:
        p = Process(target=execute_parser, args=(frontend.to_dict(),))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
