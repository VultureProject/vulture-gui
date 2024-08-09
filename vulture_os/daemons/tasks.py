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
__author__ = "Théo Bertin"
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Vultured tasks and jobs'


# Django system imports
from django.conf import settings

# Django project imports
from system.cluster.models import Cluster

# Extern modules imports
from threading import Thread, Event

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('daemon')


class TasksJob(Thread):

    def __init__(self, delay, **kwargs):
        super().__init__(**kwargs)
        # The shutdown_flag is a threading.Event object that
        # indicates whether the thread should be terminated.
        self.shutdown_flag = Event()
        self.delay = delay

    def run(self):
        logger.info("Tasks job started.")
        node = None

        # While we are not asked to terminate
        while not self.shutdown_flag.wait(self.delay):
            if not node:
                node = Cluster.get_current_node()
                if not node:
                    logger.error("Cluster::tasks: Could not get local Node configuration")
                    continue
            try:
                tasks = node.get_pending_messages(count=1)
                while not self.shutdown_flag.is_set() and tasks:
                    for task in tasks:
                        status, result = task.execute()
                        logger.debug(f"TaskJob::execute_tasks: task {task.action} results are ({status}, '{result}')")
                    tasks = node.get_pending_messages(count=1)
            except Exception as e:
                logger.exception("Tasks job failure: {}".format(e))
                logger.info("Resuming ...")

        logger.info("Tasks job finished.")

    def stop(self):
        logger.info("Tasks shutdown asked!")
        self.shutdown_flag.set()
