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
__doc__ = 'Netskope API Parser'


import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from datetime import datetime, timedelta

import json

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')



class NetskopeAPIError(Exception):
    pass



class NetskopeParser(ApiParser):
    ALERTS_ENDPOINT = "/api/v2/events/data/alert"
    BULK_SIZE = 1000

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.netskope_host = data["netskope_host"]
        self.netskope_apikey = data["netskope_apikey"]

        self.upper_timestamp = int(self.frontend.last_api_call.timestamp()) if self.frontend.last_api_call \
                                                                                        else 0

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers.update({'Netskope-Api-Token': self.netskope_apikey})
                for k,v in self.HEADERS.items():
                    self.session.headers.update({k:v})

        except Exception as err:
            raise NetskopeAPIError(err)


    def test(self):
        try:
            logs = self.get_logs(timezone.now()-timedelta(days=10))

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(e)
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since, cursor=0):
        self._connect()

        alert_url = f"https://{self.netskope_host}{self.ALERTS_ENDPOINT}"

        # Format timestamp for query, API wants a Z at the end
        if isinstance(since, datetime):
            since = int(since.timestamp())
        query = {
            'starttime': since,
            'endtime': int(timezone.now().timestamp()),
            'limit': 1000,
            'offset': cursor
        }
        result = self.session.get(alert_url, params=query).json()
        assert result['ok'] == 1, result['message']
        return result

    def parse_log(self, log):
        if log['timestamp'] > self.upper_timestamp:
            self.upper_timestamp = log['timestamp']
        log['alert_type'] = log['alert_type'].lower()
        return json.dumps(log)

    def execute(self):

        since = self.last_api_call or (datetime.utcnow() - timedelta(hours=24))
        offset = 0

        while offset%self.BULK_SIZE == 0:

            response = self.get_logs(since, offset)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            logs = response['result']
            offset += len(logs)

            self.write_to_file([self.parse_log(l) for l in logs])

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            if len(logs) > 0:
                self.frontend.last_api_call = timezone.make_aware(datetime.fromtimestamp(self.upper_timestamp)+timedelta(seconds=1))

        logger.info("Netskope parser ending.")
