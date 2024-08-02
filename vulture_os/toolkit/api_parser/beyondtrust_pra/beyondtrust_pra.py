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
__doc__ = 'Beyondtrust PRA API'
__parser__ = 'Beyondtrust PRA'

import base64
import json
import logging
import time

import requests
import xmltodict

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class BeyondtrustPRAAPIError(Exception):
    pass


class BeyondtrustPRAParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    DURATION = 0  # Fetch all logs

    def __init__(self, data):
        super().__init__(data)

        self.beyondtrust_pra_client_id = data["beyondtrust_pra_client_id"]
        self.beyondtrust_pra_secret = data["beyondtrust_pra_secret"]
        self.beyondtrust_pra_host = data["beyondtrust_pra_host"]
        self.beyondtrust_pra_api_token = data.get("beyondtrust_pra_api_token", {})

        if not self.beyondtrust_pra_host.startswith('https://') and not self.beyondtrust_pra_host.startswith('http://'):
            self.beyondtrust_pra_host = f"https://{self.beyondtrust_pra_host}"
        self.beyondtrust_pra_host = self.beyondtrust_pra_host.rstrip("/")

        self.basic_auth = self.__to_b64(f"{self.beyondtrust_pra_client_id}:{self.beyondtrust_pra_secret}")

        self.session = None

    @staticmethod
    def __to_b64(data):
        return str(base64.b64encode(bytes(data, 'utf-8')), 'utf8')

    def save_access_token(self):
        try:
            if self.frontend:
                self.frontend.beyondtrust_pra_api_token = self.beyondtrust_pra_api_token
                self.frontend.save()
        except Exception as e:
            raise BeyondtrustPRAAPIError(f"Unable to save access token: {e}")

    @property
    def api_token(self):
        if not self.beyondtrust_pra_api_token or datetime.fromtimestamp(self.beyondtrust_pra_api_token['timestamp']) + timedelta(seconds=3590) < datetime.now():
            self.beyondtrust_pra_api_token = dict(bearer=self.get_token(), timestamp=datetime.now().timestamp())
            self.save_access_token()
        return self.beyondtrust_pra_api_token['bearer']

    def get_token(self):
        res = requests.post(f'{self.beyondtrust_pra_host}/oauth2/token',
                            data={"grant_type": "client_credentials"},
                            headers={"Authorization": f"Basic {self.basic_auth}"})
        res.raise_for_status()
        return res.json()['access_token']

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                headers = self.HEADERS
                headers.update({'Authorization': f"Bearer {self.api_token}"})
                self.session.headers.update(headers)
        except Exception as err:
            raise BeyondtrustPRAAPIError(err)

    def __execute_query(self, url, query=None, timeout=20):
        if self.session is None:
            self._connect()

        msg = f"URL : {url} Query : {str(query)}"
        logger.info(f"[{__parser__}] Request API : {msg}", extra={'frontend': str(self.frontend)})

        retry = 0
        while retry < 2:
            response = self.session.get(
                url,
                params=query,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            )
            # handler rate limit exceeding
            if response.status_code == 429:
                logger.info(f"[{__parser__}]:execute: API Rate limit exceeded, waiting 10 seconds...",
                            extra={'frontend': str(self.frontend)})
                time.sleep(10)
                retry += 1
                continue
            elif response.status_code != 200:
                raise BeyondtrustPRAAPIError(
                    f"Error at Beyondtrust PRA API Call URL: {url} Code: {response.status_code} Content: {response.content}")
            else:
                return response

    def test(self):
        # Get the last 12 hours
        since = int((timezone.now() - timedelta(hours=12)).timestamp())
        try:
            logs = self.get_logs("reporting", "Team", since)

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

    def get_logs(self, resource: str, requested_type: str, since: int):
        url = f"{self.beyondtrust_pra_host}/api/{resource}"

        parameters = {
            'start_time': since,
            'duration': self.DURATION,
            'generate_report': requested_type,
        }

        res = self.__execute_query(url, query=parameters)

        logs = xmltodict.parse(res.text)

        # Return only list of events
        logs_mapping = {
            "reporting": {
                "Team": logs.get('team_activity_list', {}).get('team_activity'),
                "AccessSession": logs.get('session_list', {}).get('session'),
                "VaultAccountActivity": logs.get('vault_account_activity_list', {}).get('vault_account_activity')
            }
        }

        return logs_mapping[resource][requested_type]

    @staticmethod
    def format_log(log, resource, requested_type):
        log["resource"] = resource
        log["requested_type"] = requested_type
        return json.dumps(log)

    def execute(self):

        since = int((self.frontend.last_api_call or (timezone.now() - timedelta(days=30))).timestamp())

        # Get reporting logs
        reporting_types = ["Team", "AccessSession", "VaultAccountActivity"]

        for report_type in reporting_types:
            logs = self.get_logs("reporting", report_type, since)
            self.write_to_file([self.format_log(log, "reporting", report_type) for log in logs])
            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

        self.frontend.last_api_call = timezone.now()
        self.frontend.save()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
