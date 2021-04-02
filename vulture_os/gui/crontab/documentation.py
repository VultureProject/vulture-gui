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
import tarfile
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')

DOC_PATH = f"/zroot/apache{settings.DOCUMENTATION_PATH}"


def get_version():
    with open('/home/vlt-os/vulture_os/gui_version', 'r') as f:
        return f.read().strip()


def get_current_sha():
    with open(f"{DOC_PATH}/doc.sha", 'r') as f:
        return f.read().strip()


def doc_update(filename=None):

    proxy = get_proxy()

    if not filename:
        filename = get_version()

    try:
        sha_uri = f"https://download.vultureproject.org/v4/doc/{filename}.sha"
        r = requests.get(sha_uri, proxies=proxy)

        if r.status_code == 404 and filename != "master":
            doc_update("master")
            return

        sha = r.content.decode().strip()
        try:
            current_sha = get_current_sha()
            if current_sha == sha:
                logger.debug("[DOCUMENTATION] Identical SHA. Passing")
                return
        except FileNotFoundError:
            pass
    
        logger.info("[DOCUMENTATION] New version is available. Download it")

        # Write sha
        with open(f"{DOC_PATH}/doc.sha", 'w') as f:
            f.write(sha)
    
        # Download documentation
        doc_uri = f"https://download.vultureproject.org/v4/doc/{filename}.tar.gz"
        doc = requests.get(doc_uri, proxies=proxy)
        with open(f"{DOC_PATH}/{filename}.tar.gz", 'wb') as f:
            f.write(doc.content)

        tf = tarfile.open(f"{DOC_PATH}/{filename}.tar.gz")
        tf.extractall(f"{DOC_PATH}/")
    
    except Exception as e:
        logger.error("Crontab::doc_update: {}".format(e), exc_info=1)
        raise
