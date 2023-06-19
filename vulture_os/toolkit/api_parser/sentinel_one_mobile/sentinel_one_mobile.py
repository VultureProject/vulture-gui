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
__author__ = "Nicolas Lançon"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Sentinel One Mobile API Parser toolkit'
__parser__ = 'SENTINEL ONE MOBILE'


import datetime
import time
import requests
import json
import logging

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SentinelOneMobileAPIError(Exception):
    pass

class SentinelOneMobileParser(ApiParser):
    ALERT_URI = "api/v1/devices/public/device_updates"

    def __init__(self, data):
        super().__init__(data)

        self.sentinel_one_mobile_host = data["sentinel_one_mobile_host"]
        if not self.sentinel_one_mobile_host.startswith('https://'):
            self.sentinel_one_mobile_host = f"https://{self.sentinel_one_mobile_host}"

        self.sentinel_one_mobile_apikey = data["sentinel_one_mobile_apikey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
        except Exception as err:
            raise SentinelOneMobileAPIError(err)
        else:
            return True

    def execute_query(self, method, url, query=None, sleep_retry=10, timeout=10):
        self._connect()

        headers = {
            "api_key": self.sentinel_one_mobile_apikey,
            'Accept': 'application/json'
        }

        response = None
        retry = 3

        while retry > 0:
            retry -= 1

            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=query,
                    headers=headers,
                    proxies=self.proxies,
                    timeout=timeout
                )
            except requests.exceptions.ReadTimeout:
                msg = f"ReadTimeout, waiting {sleep_retry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleep_retry)
                continue
            except requests.exceptions.ConnectionError:
                msg = f"ConnectionError, waiting {sleep_retry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleep_retry)
                continue
            if response.status_code != 200:
                msg = f"Status Code {response.status_code}, waiting {sleep_retry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleep_retry)
                continue
            break  # no error we break from the loop

        if response is None or response.status_code != 200:
            if response is None:
                msg = f"Error Cybereason API Call URL: {url} [TIMEOUT]"
                logger.error(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
            else:
                msg = f"Error Cybereason API Call URL: {url} [TIMEOUT], Code: {response.status_code}"
                logger.error(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
            return {}
        return response.json()

    def get_logs(self, since, to):
        self._connect()

        alert_uri = f"{self.sentinel_one_mobile_host}/{self.ALERT_URI}"

        # Reformat datetimes
        to = to.isoformat()
        since = since.isoformat()

        query_size = 1000

        query = {"page": 0, "size": query_size, "excludeDeleted": "true"}

        time_field_name = "updatedAt"

        if since:
            query[f"rsql={time_field_name}=gt="] = since
        if to:
            query[f"rsql={time_field_name}=lte="] = to

        logs = []
        while True:
            ret = self.execute_query("GET", alert_uri, query)
            logs.extend(ret.get('content', []))
            if ret.get('numberOfElements', 0) == 0 or ret.get('last', True) is True:
                break
            query['page'] += 1

        return logs

    def test(self):
        logger.info(f"[{__parser__}]:test: launching test query (getting logs from 10 days ago)",
                    extra={'frontend': str(self.frontend)})

        to = timezone.now()
        since = to - timedelta(days=10)

        try:
            logs = self.get_logs(since=since, to=to)

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def execute(self):
        since = self.last_api_call or (timezone.now() - timedelta(hours=24))
        # Fetch at most 24h of logs to avoid the parser running for too long
        to = min(timezone.now(), since + timedelta(hours=24))

        logs = self.get_logs(since, to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        logger.info(f"[{__parser__}]:execute: fetched {len(logs)} logs",
                    extra={'frontend': str(self.frontend)})

        self.write_to_file([json.dumps(line) for line in logs])

        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        if len(logs) > 0:
            self.frontend.last_api_call = to

        elif self.last_api_call < timezone.now() - timedelta(hours=24):
            # If no logs where retrieved during the last 24hours,
            # move forward 1h to prevent stagnate ad vitam eternam
            self.frontend.last_api_call += timedelta(hours=1)
            logger.info(f"[{__parser__}]:execute: No recent alert found and last_api_call too old - "
                        f"setting it to {self.frontend.last_api_call}",
                        extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: update last_api_call to {self.frontend.last_api_call}",
                    extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: ### End of collect ###\r\n", extra={'frontend': str(self.frontend)})
