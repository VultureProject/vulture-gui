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
__doc__ = 'Carbon Black EDR API Parser'
__parser__ = 'CARBON BLACK'


import json
import logging
import requests

from datetime import datetime, timedelta
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CarbonBlackAPIError(Exception):
    pass


class CarbonBlackParser(ApiParser):
    ALERTS = "{}/appservices/v6/orgs/{}/alerts/_search"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json, text/plain, */*'
    }

    def __init__(self, data):
        super().__init__(data)

        self.carbon_black_host = data["carbon_black_host"]
        if not self.carbon_black_host.startswith('https://'):
            self.carbon_black_host = f"https://{self.carbon_black_host}"

        self.carbon_black_orgkey = data["carbon_black_orgkey"]
        self.carbon_black_apikey = data["carbon_black_apikey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers.update({'X-Auth-Token': self.carbon_black_apikey})
            return True
        except Exception as err:
            raise CarbonBlackAPIError(err)

    def __execute_query(self, method, url, query, timeout=10):

        self._connect()

        if method == "GET":
            response = self.session.get(
                url,
                params=query,
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        elif method == "POST":
            response = self.session.post(
                url,
                json=query,
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        else:
            raise CarbonBlackAPIError(f"Request method unrecognized : {method}")

        if response.status_code != 200:
            raise CarbonBlackAPIError(f"Error at CarbonBlack API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):
        try:
            logs = self.get_logs(since=(datetime.utcnow()-timedelta(days=10)).isoformat()+"Z")

            return {
                "status": True,
                "data": [self.format_log(log) for log in logs['results']]
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:__execute_query: {e}",
                             extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, cursor=0, since=None):
        alert_url = self.ALERTS.format(self.carbon_black_host, self.carbon_black_orgkey)

        # Format timestamp for query, API wants a Z at the end
        if isinstance(since, datetime):
            since = since.isoformat()
        since = since.replace("+00:00", "Z")
        if since[-1] != "Z":
            since += "Z"

        query = {
            'criteria': {
                'category': ['THREAT'],
                'group_results': True,
                'last_update_time': {
                    'start': since,
                    'end': datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
                }
            },
            'rows': 9999,
            'start': cursor
        }

        return self.__execute_query("POST", alert_url, query)

    def format_log(self, log):
        log['observer_name'] = self.carbon_black_host.replace("https://", "")
        log['url'] = self.carbon_black_host
        return json.dumps(log)

    def execute(self):

        since = self.last_api_call or (datetime.utcnow() - timedelta(hours=24))

        available = 0
        found = 0
        while available <= found:

            response = self.get_logs(available, since)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            logs = response['results']
            found = int(response['num_found'])
            # available key is not present if response = {'results': [], 'num_found': 0}
            available = int(response.get('num_available', "0")) + 1

            self.write_to_file([self.format_log(l) for l in logs])

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            if len(logs) > 0:
                # API returns alerts sorted, first is newer
                # Replace "Z" by "+00:00" for datetime parsing
                self.frontend.last_api_call = datetime.fromisoformat(logs[0]['last_update_time'].replace("Z", "+00:00"))+timedelta(milliseconds=1)

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

