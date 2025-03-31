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
__author__ = "nlancon"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Extrahop API Parser'
__parser__ = 'EXTRAHOP'

import json
import logging
from django.conf import settings
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser
from datetime import timedelta, datetime

import requests
from requests.auth import HTTPBasicAuth

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ExtrahopAPIError(Exception):
    pass


class ExtrahopParser(ApiParser):

    HEADERS = {
        "Accept": "application/json"
    }

    def __init__(self, data):
        super().__init__(data)

        self.extrahop_host = data["extrahop_host"].rstrip("/")
        if not self.extrahop_host.startswith('https://'):
            self.extrahop_host = f"https://{self.extrahop_host}"

        self.id = data['extrahop_id']
        self.secret = data['extrahop_secret']

        self.access_token = data.get('extrahop_access_token')
        self.expire_date = data.get('extrahop_expire_date')

        self.session = None

    def get_access_token(self):
        if not self.access_token or self.expire_date < timezone.now() + timedelta(minutes=5):
            try:
                url = f"{self.extrahop_host}/oauth2/token"
                auth = HTTPBasicAuth(self.id, self.secret)
                response = requests.post(url, auth=auth, data={"grant_type": "client_credentials"})
                response.raise_for_status()
            except requests.exceptions.HTTPError as err:
                raise ExtrahopAPIError(f"Unable de renew access token. Error: {err}")
            else:
                response_json = response.json()
                self.access_token = response_json["access_token"]
                self.expire_date = (timezone.now() + timedelta(seconds=int(response_json["expires_in"]))).isoformat()
                if self.frontend:
                    self.frontend.access_token = self.access_token
                    self.frontend.expire_date = self.expire_date
                    self.frontend.save()

        return self.access_token

    def _execute_query(self, method, url, query, timeout=10):
        """
        raw request doesn't handle the pagination natively
        """
        max_retry = 3
        retry = 1
        while retry <= max_retry:
            if self.session is None:
                self._connect()

            msg = f"call {url} with query {query} (retry: {retry})"
            logger.debug(f"[{__parser__}]:__execute_query: {msg}", extra={'frontend': str(self.frontend)})
            if method == "POST":
                try:
                    response = self.session.post(
                        url,
                        json=query,
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                    )

                except Exception as e:
                    logger.debug(f"[{__parser__}]:__execute_query: Exception: {e}", extra={'frontend': str(self.frontend)})
                    self.session = None
                    self.access_token = None
            else:
                raise ExtrahopAPIError(f"Error at request, unknown method : {method}")

            if response.status_code == 200:
                break
            elif response.status_code == 204:
                return []

            if "The specified access token is invalid." in response.text:
                # Force fetching a new token
                logger.debug(f"[{__parser__}]:__execute_query: Force fetching a new token", extra={'frontend': str(self.frontend)})
                self.session = None
                self.access_token = None

            logger.debug(f"[{__parser__}]:__execute_query: retry += 1 (waiting 10s)",
                         extra={'frontend': str(self.frontend)})
            retry += 1
            self.evt_stop.wait(10.0)

        # response.raise_for_status()
        if response.status_code != 200:
            logger.error(f"[{__parser__}]:__execute_query: Error at Extrahop API Call URL: {url} Code: {response.status_code} Content: {response.content}\n" \
                f"Response : {response}", extra={'frontend': str(self.frontend)})
            raise ExtrahopAPIError(
                f"Error at Extrahop API Call URL: {url} Code: {response.status_code} Content: {response.content}\n" \
                f"Response : {response}")

        return response.json()

    def _connect(self):
        if self.session is None:
            self.session = requests.Session()
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Bearer {self.get_access_token()}"})
        return True

    def test(self):
        try:
            if self.session is None:
                self._connect()

            since = timezone.now() - timedelta(hours=24)

            response = self.get_logs(since)

            return {
                "status": True,
                "data": response
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since):
        if self.session is None:
            self._connect()

        url = f"{self.extrahop_host}/api/v1/detections/search"
        payload = {
            "create_time": int(since.timestamp() * 1000),
        }
        return self._execute_query("POST", url, payload)

    @staticmethod
    def format_log(log):
        log['timestamp_iso'] = datetime.fromtimestamp(log['create_time']/1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
        return json.dumps(log)

    def execute(self):
        since = self.last_api_call or (timezone.now() - timedelta(days=30))
        to = timezone.now()

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        if logs := self.get_logs(since):
            max_timestamp = max(x['create_time'] for x in logs)
            self.write_to_file([self.format_log(log) for log in logs])

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            max_timestamp += 1  # since is inclusif
            self.frontend.last_api_call = datetime.fromtimestamp(max_timestamp/1000.0, tz=timezone.utc)

        else:
            logger.info(f"[{__parser__}]:execute: Fetched 0 log.", extra={'frontend': str(self.frontend)})
            self.frontend.last_api_call = to

        self.frontend.save()
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
