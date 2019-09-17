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
__credits__ = ["Kevin GUILLEMOT"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Job for OS Monitoring'


# Django system imports
from django.conf import settings

# Extern modules imports
import json
from time import sleep
from threading import Thread, Event

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')

# Redis import
from toolkit.redis.redis_base import RedisBase

# Mongo import
from toolkit.mongodb.mongo_base import MongoBase


def reconcile():
    # MONGO #
    m = MongoBase()
    if not m.connect():
        return False
    m.connect_primary()

    # REDIS #
    r = RedisBase()
    master_node = r.get_master()
    r = RedisBase(node=master_node)

    redis_list_name = "logs_darwin"
    ignored_alerts = list()

    rangeLen = r.redis.llen(redis_list_name)
    alerts = r.redis.lrange(redis_list_name, "0", str(rangeLen-1))
    r.redis.ltrim(redis_list_name, str(rangeLen), "-1")

    for alert in alerts:
        alert = str(alert, "utf-8")
        a = json.loads(alert)
        evt_id = a.get("evt_id")
        if evt_id is None:
            ignored_alerts.append(a)
            continue
        query = {"darwin_id": evt_id}
        newvalue = {"$set": {"darwin_alert_details": a, "darwin_is_alert": True}}
        m.update_one("logs", query, newvalue)
    return True


class ReconcileJob(Thread):

    def __init__(self, delay):
        super().__init__()
        # The shutdown_flag is a threading.Event object that
        # indicates whether the thread should be terminated.
        self.shutdown_flag = Event()
        self.delay = delay

    def run(self):
        logger.info("Reconcile job started.")

        # While we are not asked to terminate
        while not self.shutdown_flag.is_set():
            try:
                reconcile()
            except Exception as e:
                logger.error("Reconcile job failure: ")
                logger.info("Resuming ...")

            # Do not sleep if we have to quit
            if not self.shutdown_flag.is_set():
                # sleep DELAY time
                sleep(self.delay)

        logger.info("Reconcile job stopped.")

    def ask_shutdown(self):
        logger.info("Shutdown asked !")
        self.shutdown_flag.set()
