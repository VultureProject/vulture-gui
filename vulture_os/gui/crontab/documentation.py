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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Job for documentation update'

from django.conf import settings
from toolkit.network.network import get_proxy

import requests
import zipfile
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


def doc_update():

    proxy = get_proxy()
    try:
        doc_uri = "https://github.com/VultureProject/vulture-doc/archive/master.zip"
        doc = requests.get(doc_uri, proxies=proxy)
        logger.debug("Crontab::doc_update: Downloading DOC from Github")

        with open("/zroot/apache" + settings.DOCUMENTATION_PATH + "/" + "master.zip", "wb") as f:
            f.write(doc.content)

        with zipfile.ZipFile("/zroot/apache" + settings.DOCUMENTATION_PATH + "/master.zip", 'r') as zip_ref:
            zip_ref.extractall("/zroot/apache" + settings.DOCUMENTATION_PATH + "/")

    except Exception as e:
        logger.error("Crontab::doc_update: {}".format(e), exc_info=1)
        raise
