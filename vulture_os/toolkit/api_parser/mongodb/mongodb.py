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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'MongoDB API Parser'
__parser__ = 'MONGODB'

import datetime
import gzip
import logging
import requests

from django.conf import settings
from django.utils import timezone
from vulture_os.toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class MongoDBParseError(Exception):
    pass


class MongoDBAPIError(Exception):
    pass


class MongoDBParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.base_url = "https://cloud.mongodb.com/api/atlas/v1.0"
        self.username = data['mongodb_api_user']
        self.password = data['mongodb_api_password']
        self.group_id = data['mongodb_api_group_id']

    def _connect(self):
        if self.session is None:
            self.session = requests.Session()
            self.session.auth = requests.auth.HTTPDigestAuth(self.username, self.password)
        return True

    def test(self):
        try:
            startDate = timezone.now()
            startDate = startDate.replace(minute=0, second=0, microsecond=0)
            startDate = startDate.timestamp() * 1000

            url = f"{self.start_console_uri}startDate={int(startDate)}&endDate=0&token=none"

            r = requests.get(
                url,
                headers=self.HEADERS,
                proxies=self.proxies,
                allow_redirects=False,
                timeout=10,
                stream=True
            )

            if "Retry-After" in r.headers.keys():
                return {
                    "status": False,
                    "error": r.content.decode('UTF-8')
                }

            status = True
            if r.status_code == 200:
                status = False

            return {
                "status": status,
                "data": "Response : {}".format("OK" if status else r.status_code)
            }
        except MongoDBAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self):
        self.update_lock()

        # FIXME : Doc sais every 5 minutes
        if self.last_api_call.replace(minute=0, second=0, microsecond=0) > timezone.now().replace(minute=0, second=0, microsecond=0)-datetime.timedelta(hours=1)\
                or timezone.now().minute < 30:
            return

        try:
            self._connect()

            # First, retrieve hostnames clusters with group_id
            url = self.base_url+"/groups/{}/clusters"

            response = self.session.get(
                url,
                proxies=self.proxies
            )

            try:
                response.raise_for_status()
                hostnames = [c['name'] for c in response.json()['results']]
            except Exception as err:
                raise MongoDBAPIError(err)

            for hostname in hostnames:
                msg = f"Retrieve logs from hostname {hostname}"
                logger.info(f"{[__parser__]}:{self.execute.__name__}: {msg}", extra={'frontend': str(self.frontend)})

                url = self.base_url+"/groups/{}/logs/mongos.gz"
                response = self.session.get(
                    url,
                    proxies=self.proxies
                )

                response.raise_for_status()

                uncompressed = gzip.decompress(response.content)
                lines = uncompressed.split("\n")

                # Retrieve timestamp of last line

                # And send to Rsyslog
                self.write_to_file(lines)

        except Exception as e:
            raise MongoDBParseError(e)
