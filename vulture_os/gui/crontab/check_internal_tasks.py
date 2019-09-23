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
__doc__ = 'Job for documentation update'

from system.cluster.models import MessageQueue, Cluster
from toolkit.mongodb.mongo_base import MongoBase
from django.utils.timezone import make_aware
from django.conf import settings
import datetime
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


def check_internal_tasks():
    try:
        # Run this crontab only on master node
        node = Cluster.get_current_node()
        if not node.is_master_mongo:
            return

        # Deleting done internal tasks older than a month
        last_month_date = make_aware(datetime.datetime.now() - datetime.timedelta(days=30))
        MessageQueue.objects.filter(status="done", date_add__lte=last_month_date).delete()

        # Checking if a node has not executing his duty since a while.
        # If so, removing it from the cluster
        message_queue_not_finished = MessageQueue.objects.filter(date_add__lt=last_month_date, status="new")

        node_to_remove = []
        for message in message_queue_not_finished:
            if message.node not in node_to_remove:
                node_to_remove.append(message.node)

            message.delete()

        for n in node_to_remove:
            logger.info('[REMOVING DEAD NODE FROM CLUSTER] Node: {}'.format(n.name))
            c = MongoBase()
            c.connect_primary()
            c.repl_remove(n.name + ":9091")

    except Exception as e:
        logger.error("Crontab::check_internal_tasks: {}".format(e), exc_info=1)
        raise
