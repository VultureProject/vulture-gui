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
__author__ = "Mael Bonniot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'SignalSciences Ngwaf API Parser'
__parser__ = 'SIGNALSCIENCES_NGWAF'

import json
import logging
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
        self.signalsciences_ngwaf_corp_name = data["signalsciences_ngwaf_corp_name"]
        self.signalsciences_ngwaf_site_name = data["signalsciences_ngwaf_site_name"]

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
            raise SignalSciencesNgwafAPIError(f"{[__parser__]}:connect: An error occurred when creating http session : {str(e)}")


    def __execute_query(self, url, query=None, timeout=10):
        try:
            self._connect()

            response = self.session.get(
                url,
                params=query,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl)

            if response.status_code != 200:
                raise SignalSciencesNgwafAPIError(
                    f"Error at SafenetAPI Call URL: {url} Code: {response.status_code} Content: {response.content}")

            return response.json()

        except Exception as e:
            logger.exception(f"{[__parser__]}:__execute_query: {str(e)}", extra={'frontend': str(self.frontend)})
            raise SignalSciencesNgwafAPIError(f"{[__parser__]}:__execute_query: An error occurred while executing query : {str(e)}")


    def test(self):
        current_time = timezone.now().replace(second=0, microsecond=0)
        try:
            logs = self.get_logs(
                self.API_BASE_URL + f'/api/v0/corps/{self.signalsciences_ngwaf_corp_name}/sites/{self.signalsciences_ngwaf_site_name}/feed/requests',
                since = current_time - timedelta(minutes=6),
                to = current_time - timedelta(minutes=5))

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


    def get_logs(self, url, since, to):
        try:
            query = {}

            if isinstance(since, datetime):
                query['from'] = int(since.timestamp() / 60) * 60
            if isinstance(to, datetime):
                query['until'] = int(to.timestamp() / 60) * 60

            return self.__execute_query(url, query)

        except Exception as e:
            logger.exception(f"{[__parser__]}:get_logs: {str(e)}", extra={'frontend': str(self.frontend)})
            raise SignalSciencesNgwafAPIError(f"{[__parser__]}:get_logs: An error occurred while trying to get logs : {str(e)}")


    def _format_log(self, log):
        try:
            if timestamp := log.pop('timestamp', None):
                log['@timestamp'] = timestamp
            else:
                logger.exception(f"{[__parser__]}:_format_log: {str(e)}", extra={'frontend': str(self.frontend)})
                raise SignalSciencesNgwafAPIError(f"{[__parser__]}:_format_log: Missing timestamp from log {log}")

            log['header'] = {'client': {}, 'server': {}}
            if headersIn := log.pop("headersIn", None):
                for elem in headersIn:
                    log['header']['client'][str(elem[0]).lower()] = str(elem[1])
            if headersOut := log.pop("headersOut", None):
                for elem in headersOut:
                    log['header']['server'][str(elem[0]).lower()] = str(elem[1])

            for tag in log.get("tags"):
                tag['value'] = str(tag['value'])

            return json.dumps(log)

        except Exception as e:
            logger.exception(f"{[__parser__]}:_format_log: {str(e)}", extra={'frontend': str(self.frontend)})
            return None


    def execute(self):
        try:
            # If we're late about 24h -> move forward 1h to prevent API error
            if self.frontend.last_api_call < timezone.now() - timedelta(hours=24):
                self.frontend.last_api_call = timezone.now() - timedelta(hours=23)

            #TODO:while self.frontend.last_api_call < timezone.now() - timedelta(minutes=6):
            since = min(self.frontend.last_api_call, timezone.now() - timedelta(minutes=6))
            to = min(timezone.now() - timedelta(minutes=5), since + timedelta(minutes=1))

            logger.info(f"[{__parser__}]:execute: Start collecting logs from {since} to {to}", extra={'frontend': str(self.frontend)})

            response = self.get_logs(
                    self.API_BASE_URL + f'/api/v0/corps/{self.signalsciences_ngwaf_corp_name}/sites/{self.signalsciences_ngwaf_site_name}/feed/requests',
                    since,
                    to)
            self.update_lock()

            if logs := response.get("data"):
                self.write_to_file([self._format_log(log) for log in logs if log])
                self.update_lock()

                if next_url := response.get("next", {}).get("uri", {}):
                    response = self.get_logs(self.API_BASE_URL + next_url, since, to)
                    self.update_lock()

                self.frontend.last_api_call = to

            logger.info(f"[{__parser__}]:execute: Parsing done", extra={'frontend': str(self.frontend)})

        except Exception as e:
            logger.exception(f"{[__parser__]}:execute: {str(e)}", extra={'frontend': str(self.frontend)})
            raise SignalSciencesNgwafAPIError(f"{[__parser__]}:execute: An error occurred on main method : {str(e)}")
