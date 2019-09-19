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
__doc__ = 'Job for RSS'

from system.cluster.models import Cluster
from django.conf import settings
from gui.models.rss import RSS
from toolkit.network.network import get_proxy

import requests
import datetime

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


def rss_fetch():
    if not Cluster.get_current_node().is_master_mongo:
        logger.debug("Crontab::rss_fetch: Not the master node, passing RSS fetch")
        return

    proxy = get_proxy()
    try:
        rss_uri = "https://predator.vultureproject.org/news.json"
        infos = requests.get(rss_uri, proxies=proxy).json()
        logger.debug("Crontab::rss_fetch: Received {} RSS feed".format(len(infos)))
        for info in infos:
            try:
                RSS.objects.get(title=info['title'])
            except RSS.DoesNotExist:
                RSS.objects.create(
                    title=info['title'],
                    date=datetime.datetime.strptime(info['timestamp'], "%d/%m/%Y %H:%M:%S"),
                    level=info['level'],
                    content=info["content"]
                )

    except Exception as e:
        logger.error("Crontab::rss_fetch: {}".format(e), exc_info=1)
        raise
