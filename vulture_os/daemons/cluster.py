#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Jérémie JOURDIN"
__credits__ = ["Kevin GUILLEMOT", "Théo Bertin"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cluster daemon'


import os
import sys

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('daemon')

from daemons.monitor import MonitorJob
from daemons.tasks import TasksJob
from signal import signal, SIGTERM, SIGINT
from threading import Event

SERVICE_SHUTDOWN = Event()
JOB_DEFINITIONS = {
    'tasks': {
        'function': TasksJob,
        'frequency': 5,
    },
    'monitor': {
        'function': MonitorJob,
        'frequency': 10,
    }
}
RUNNING_JOBS = dict()

def service_shutdown(signum, _):
    logger.debug(f'Caught signal {signum}')
    SERVICE_SHUTDOWN.set()
    for jobname, job in RUNNING_JOBS.items():
        logger.debug(f"asking {jobname} to stop...")
        job.stop()



""" This is for the cluster daemon process """
if __name__ == '__main__':
    """ Launch jobs """
    SERVICE_SHUTDOWN.clear()
    logger.info("Vultured started.")

    for jobname, jobdef in JOB_DEFINITIONS.items():
        logger.info(f"Vultured:: starting job {jobname}")
        job = jobdef['function'](jobdef['frequency'], name=jobname)
        job.start()
        RUNNING_JOBS[jobname] = job

    signal(SIGTERM, service_shutdown)
    signal(SIGINT, service_shutdown)

    while not SERVICE_SHUTDOWN.wait(5):
        for jobname, job in RUNNING_JOBS.items():
            if not job.is_alive():
                logger.warning(f"Vultured:: job {jobname} crashed, relauching...")
                try:
                    jobdef = JOB_DEFINITIONS[jobname]
                    job.join()
                    job = jobdef['function'](jobdef['frequency'], name=jobname)
                    job.start()
                    RUNNING_JOBS[jobname] = job
                except Exception:
                    logger.error(f"Vultured:: Failed restarting job {jobname}!")
                    continue

    logger.info("Vultured stopping...")
    for job in RUNNING_JOBS.values():
        job.join()

    logger.info("Vultured stopped.")
