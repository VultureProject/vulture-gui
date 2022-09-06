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
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Rapid7 InsightIDR API Parser'
__parser__ = 'RAPID7 IDR'

import json
import logging
import requests

from datetime import datetime, timedelta, timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class Rapid7IDRAPIError(Exception):
    pass


class Rapid7IDRParser(ApiParser):
    VALIDATE_ENDPOINT = "/validate"
    INVESTIGATIONS_ENDPOINT = "/idr/v1/investigations"
    INVESTIGATION_URL = "https://insight.rapid7.com/login#/investigations"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.rapid7_idr_host = data["rapid7_idr_host"].rstrip("/")
        if not self.rapid7_idr_host.startswith('https://'):
            self.rapid7_idr_host = f"https://{self.rapid7_idr_host}"

        self.rapid7_idr_apikey = data["rapid7_idr_apikey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                headers.update({'X-Api-Key': self.rapid7_idr_apikey})

                self.session.headers.update(headers)

            return True

        except Exception as err:
            raise Rapid7IDRAPIError(err)

    def __execute_query(self, url, query={}, timeout=10):

        self._connect()

        response = self.session.get(
            url,
            params=query,
            timeout=timeout,
            proxies=self.proxies
        )

        if response.status_code != 200:
            raise Rapid7IDRAPIError(f"Error at Rapid7 IDR API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):
        validation_url = self.rapid7_idr_host + self.VALIDATE_ENDPOINT

        try:
            result = self.__execute_query(validation_url)

            return {
                "status": True,
                "data": result["message"]
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, index=0, since=None, to=None):
        """
        Get logs from 'since' timestamp to 'to' created_time timestamp
        events with create_time equal to 'since' or 'to' are included in the match
        timestamp filtering precision is at the millisecond (microseconds ignored)

        :param index: the index of the page to fetch (for multi-page results)
        :param since: a valid and timezone-aware datetime object representing the first log when filtering through created_time
        :param to: a valid and timezone-aware datetime object representing the last log when filtering through created_time
        :returns: a json object containing the events in the 'data' list
        :raises Rapid7IDRAPIError: in case the function could not connect or the reply's status code wasn't 200
        """
        alert_url = self.rapid7_idr_host + self.INVESTIGATIONS_ENDPOINT

        # Format timestamp for query
        if isinstance(since, datetime):
            since = since.isoformat()
            since = since.replace("+00:00", "Z")
        # Format timestamp for query
        if isinstance(to, datetime):
            to = to.isoformat()
            to = to.replace("+00:00", "Z")

        query = {
            'index': index,
            'size': 1000
        }

        # logs with 'since' or 'to' values are included in return
        if since:
            query['start_time'] = since
        if to:
            query['end_time'] = to

        return self.__execute_query(alert_url, query)

    def format_log(self, log):
        log['type'] = [x['type'] for x in log['alerts']]
        log['url'] = f"{self.INVESTIGATION_URL}/{log['id']}"

        try:
            # min() works to sort ISO8601 timestamps as strings, because numbers are logically-ordered and consistent
            log['event_start'] = min([x['first_event_time'] for x in log['alerts']])
        except ValueError:
            # No first_event_time or alerts in log
            pass

        return json.dumps(log)

    def execute(self):

        since = self.last_api_call or (datetime.now(timezone.utc) - timedelta(hours=24))
        to = since
        current_time = datetime.now(timezone.utc)

        while not self.evt_stop.is_set() and to != current_time:
            # Get logs by batches of 1 hour
            to = min(current_time, to + timedelta(hours=24))
            msg = f"Parser starting from {since} to {to}"
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            index = 0
            available = 1
            retrieved = 0
            while retrieved < available:

                response = self.get_logs(index, since, to)

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                logs = response['data']

                available = int(response['metadata']['total_data'])
                msg = f"got {available} lines available"
                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                retrieved += len(logs)
                msg = f"retrieved {retrieved} lines"
                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                index += 1

                self.write_to_file([self.format_log(l) for l in logs])

                # Writting may take some while, so refresh token in Redis
                self.update_lock()

            # increment by 1ms to avoid repeating a line if its timestamp happens to be the exact timestamp 'to'
            since = to + timedelta(microseconds=1000)
            self.frontend.last_api_call = since
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
