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
__author__ = "Gaultier PARAIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cisco Umbrella API Parser'
__parser__ = 'CISCO-UMBRELLA'


import json
import logging
import requests

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CiscoUmbrellaAPIError(Exception):
    pass


class CiscoUmbrellaParser(ApiParser):
    TOKEN_URL = 'https://api.umbrella.com/auth/v2/token'
    ACTIVITY_URL = 'https://api.sse.cisco.com/reports/v2/activity/dns'
    LIMIT_MAX = 5000
    OFFSET_MAX = 10000

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.cisco_umbrella_client_id = data["cisco_umbrella_client_id"]
        self.cisco_umbrella_secret_key = data["cisco_umbrella_secret_key"]

        self.cisco_umbrella_access_token = data.get("cisco_umbrella_access_token", None)
        self.cisco_umbrella_expires_at = data.get("cisco_umbrella_expires_at", None)

        self.session = None

    def _get_token(self):
        auth = HTTPBasicAuth(self.cisco_umbrella_client_id, self.cisco_umbrella_secret_key)
        client = BackendApplicationClient(client_id=self.cisco_umbrella_client_id)
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=self.TOKEN_URL, auth=auth)
        self.cisco_umbrella_access_token = token["access_token"]
        self.cisco_umbrella_expires_at = datetime.fromtimestamp(token["expires_at"]/1000, tz=timezone.now().astimezone().tzinfo)

    def _connect(self):
        try:
            # Check for expiration with 10 seconds difference to be sure token will still be valid for some time
            if not self.cisco_umbrella_access_token or \
                not self.cisco_umbrella_expires_at or \
                    (self.cisco_umbrella_expires_at - timedelta(seconds=10)) < timezone.now():
                self._get_token()

            self.session = requests.Session()
            headers = self.HEADERS
            headers.update({'Authorization': f"Bearer {self.cisco_umbrella_access_token}"})
            self.session.headers.update(headers)

        except Exception as err:
            raise CiscoUmbrellaAPIError(err)

    def __execute_query(self, url, query, timeout=30):
        '''
        raw request doesn't handle the pagination natively
        '''
        self._connect()

        response = self.session.get(url,
            params=query,
            headers=self.HEADERS,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )

        # response.raise_for_status()
        if response.status_code != 200:
            raise CiscoUmbrellaAPIError(f"Error at Cisco-Umbrella API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):
        try:
            result = self.get_logs(timezone.now()-timedelta(hours=2), timezone.now())

            return {
                "status": True,
                "data": result
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since, to, index=0):

        payload = {
            'offset': index,
            'limit': self.LIMIT_MAX,
            'from': int(since.timestamp() * 1000),
            'to': int(to.timestamp() * 1000),
        }
        logger.debug(f"[{__parser__}]:get_alerts: Cisco-Umbrella query parameters : {payload}",
                     extra={'frontend': str(self.frontend)})
        return self.__execute_query(self.ACTIVITY_URL, payload)

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        # Due to a limitation in the API, we have update from and to dynamically
        # to collect all logs during the minute of execution
        # So this parser will keep running as long as it's not up-to-date or asked to stop
        while not self.evt_stop.is_set():
            since = self.frontend.last_api_call or (timezone.now() - timedelta(minutes=15))
            to = timezone.now()
            logger.info(f"[{__parser__}]:execute: Parser starting from {since} to {to}.", extra={'frontend': str(self.frontend)})

            index = 0
            logs_count = self.LIMIT_MAX
            while logs_count == self.LIMIT_MAX and index <= self.OFFSET_MAX:
                response = self.get_logs(since, to, index)
                # Downloading may take some while, so refresh token in Redis
                self.update_lock()
                logs = response['data']
                logs_count = len(logs)
                logger.info(f"[{__parser__}]:execute: got {logs_count} lines", extra={'frontend': str(self.frontend)})
                index += logs_count
                logger.info(f"[{__parser__}]:execute: retrieved {index} lines", extra={'frontend': str(self.frontend)})
                self.write_to_file([self.format_log(l) for l in logs])
                # Writting may take some while, so refresh token in Redis
                self.update_lock()
            # When there are more than 15000 logs, last_api_call is the timestamp of the last log
            if logs_count == self.LIMIT_MAX and index == self.OFFSET_MAX + self.LIMIT_MAX:
                timestamp = logs[-1]['timestamp']/1000
                self.frontend.last_api_call = datetime.fromtimestamp(timestamp, tz=timezone.now().astimezone().tzinfo)
            else:
                # All logs have been recovered, the parser can be stopped
                self.frontend.last_api_call = to
                break
            self.frontend.save()
        self.frontend.cisco_umbrella_access_token = self.cisco_umbrella_access_token
        self.frontend.cisco_umbrella_expires_at = self.cisco_umbrella_expires_at
        self.frontend.save()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
