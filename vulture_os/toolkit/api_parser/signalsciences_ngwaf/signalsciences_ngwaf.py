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


class SignalSciencesNgwafAPIError(Exception):
    pass


class SignalSciencesNgwafParser(ApiParser):
    API_BASE_URL = "https://dashboard.signalsciences.net"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.signalsciences_ngwaf_email = data["signalsciences_ngwaf_email"]
        self.signalsciences_ngwaf_token = data["signalsciences_ngwaf_token"]
        # corp.name & site.name

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                headers.update({
                    'x-api-user': self.signalsciences_ngwaf_email,
                    'x-api-token': self.signalsciences_ngwaf_token
                })

                self.session.headers.update(headers)

            return True

        except Exception as e:
            raise SignalSciencesNgwafAPIError(e)

    def __execute_query(self, url, query=None, timeout=10):

        self._connect()

        response = self.session.get(
            url,
            params=query,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )

        if response.status_code != 200:
            raise SignalSciencesNgwafAPIError(
                f"Error at SafenetAPI Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):
        current_time = timezone.now().replace(second=0, microsecond=0)
        try:
            logs = self.get_logs(
                since=int((current_time - timedelta(minutes=1)).timestamp()),
                to=int((current_time - timedelta(minutes=5)).timestamp()))

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
        corp_name = 'cbpgroup'
        site_name = 'prod'
        url = self.API_BASE_URL + '/api/v0/corps/%s/sites/%s/feed/requests'%(corp_name, site_name)

        query = {}
        # logs with 'since' or 'to' values are included in return
        if isinstance(since, datetime):
            query['from'] = int((since - timedelta(minutes=1)).timestamp())
        if isinstance(to, datetime):
            query['until'] = int((to - timedelta(minutes=5)).timestamp())

        # if not to and since:

        return self.__execute_query(url, query)

    def format_log(self, log):
        # adapt timestamp name field
        log['@timestamp'] = log.pop('timestamp')

        # pretty formating headers
        headers_in = log.pop("headersIn")
        for elem in headers_in:
            log['client.header.'+elem[0]] = elem[1]

        headers_out = log.pop("headersOut")
        if headers_out:
            for elem in headers_out:
                log['server.header.'+elem[0]] = elem[1]

        return json.dumps(log)

    def execute(self):
        since = self.frontend.last_api_call or (timezone.now() - timedelta(minutes=5))
        to = min(timezone.now(), since + timedelta(minutes=1))

        since = int(since.replace(second=0, microsecond=0).timestamp())
        to = int(to.replace(second=0, microsecond=0).timestamp())

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        response = self.get_logs(since, to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        logs = response.get("data")

        if logs != []:
            self.write_to_file([self.format_logs(log) for log in logs])

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        while response["next"].get("uri") != '':
            response = self.__execute_query(self.API_BASE_URL + response['next']['uri'])
            self.update_lock()
            logs = response.get("data")
            self.write_to_file([self.format_logs(log) for log in logs if log])
            self.update_lock()

            self.frontend.last_api_call = to

        if self.last_api_call < timezone.now()-timedelta(hours=24):
            # If no logs where retrieved during the last 24hours,
            # move forward 1h to prevent stagnate ad vitam eternam
            self.frontend.last_api_call += timedelta(hours=1)

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
