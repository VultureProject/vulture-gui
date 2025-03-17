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
__author__ = "Gaultier Parain"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Safenet API Parser'
__parser__ = 'SAFENET'

import json
import logging
import time

import requests

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SafenetAPIError(Exception):
    pass


class SafenetParser(ApiParser):
    API_BASE_URL = "https://api.safenetid.com/api/v1/tenants/"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.safenet_apikey = data["safenet_apikey"]
        self.safenet_tenant_code = data["safenet_tenant_code"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                headers.update({'apiKey': self.safenet_apikey})

                self.session.headers.update(headers)

            return True

        except Exception as err:
            raise SafenetAPIError(err)

    def __execute_query(self, url, query=None, timeout=10):

        self._connect()
        logger.info(f"[{__parser__}]:get_logs: URL: {url} , params: {query}", extra={'frontend': str(self.frontend)})
        response = self.session.get(
            url,
            params=query,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )

        # handler rate limit exceeding
        if response.status_code == 429:
            logger.info(f"[{__parser__}]:execute: API Rate limit exceeded, waiting 10 seconds...", extra={'frontend': str(self.frontend)})
            time.sleep(10)
            return self.__execute_query(url, query, timeout)
        elif response.status_code != 200:
            raise SafenetAPIError(
                f"Error at SafenetAPI Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):
        current_time = timezone.now()
        try:
            logs = self.get_logs(since=(current_time - timedelta(minutes=5)), to=(current_time))

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"{[__parser__]}:test: {str(e)}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since=None, to=None):
        alert_url = self.API_BASE_URL + self.safenet_tenant_code + "/logs/"

        # Format timestamp for query
        if isinstance(since, datetime):
            since = since.isoformat()
            since = since[:-9] + "Z"
        # Format timestamp for query
        if isinstance(to, datetime):
            to = to.isoformat()
            to = to[:-9] + "Z"

        query = {}

        # logs with 'since' or 'to' values are included in return
        if since:
            query['since'] = since
        if to:
            query['until'] = to

        return self.__execute_query(alert_url, query)

    def format_logs(self, log):
        return json.dumps(log)


    def execute(self):

        since = self.frontend.last_api_call or (timezone.now() - timedelta(hours=24))
        # fetch at most 24h of logs to avoid the process running for too long
        to = min(timezone.now(), since + timedelta(hours=24))

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        response = self.get_logs(since, to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        logs = response["page"]["items"]

        if logs != []:
            self.write_to_file([self.format_logs(log) for log in logs])

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        if response["page"].get("totalItems"):
            while response["links"].get("next"):
                response = self.__execute_query(response["links"]["next"])
                self.update_lock()
                logs = response["page"]["items"]
                self.write_to_file([self.format_logs(log) for log in logs])
                self.update_lock()

            # update last_api_call only if logs are retrieved
            self.frontend.last_api_call = to
        elif self.last_api_call < timezone.now()-timedelta(hours=24):
            # If no logs where retrieved during the last 24hours,
            # move forward 1h to prevent stagnate ad vitam eternam
            self.frontend.last_api_call += timedelta(hours=1)

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
