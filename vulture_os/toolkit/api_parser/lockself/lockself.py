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
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'LOCKSELF API'
__parser__ = 'LOCKSELF'

import json
import logging
import requests

from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class LockselfAPIError(Exception):
    pass

class LockselfParser(ApiParser):
    logs_endpoint = "/api-key/logs/content"

    HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    def __init__(self, data):
        super().__init__(data)

        self.lockself_x_auth_token = data["lockself_x_auth_token"]
        self.lockself_x_ls_token = data["lockself_x_ls_token"]
        self.lockself_host = data["lockself_host"]
        self.lockself_organization_id = data["lockself_organization_id"]

        self.lockself_host = data["lockself_host"].rstrip("/")
        if not self.lockself_host.startswith('https://') and not self.lockself_host.startswith('http://'):
            self.lockself_host = f"https://{self.lockself_host}"

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                self.session.headers.update(self.HEADERS)
                self.session.headers.update({'X-Auth-Token': self.lockself_x_auth_token})
                self.session.headers.update({'X-Ls-Token': self.lockself_x_ls_token})
            return True

        except Exception as err:
            raise LockselfAPIError(err)

    def execute_query(self, url, params={}, timeout=20):
        logger.info(f"[{__parser__}]:execute_query: URL: {url} , params: {params}", extra={'frontend': str(self.frontend)})
        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies,
            timeout=timeout,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != 200:
            error = f"Error at Lockself API Call: status : {response.status_code}, content : {response.content}"
            logger.error(f"[{__parser__}]:execute_query: {error}", extra={'frontend': str(self.frontend)})
            raise LockselfAPIError(error)

        return response.json()

    def get_logs(self, since, to):
            self._connect()
            url = self.lockself_host + self.logs_endpoint
            limit = 100000
            query = {
                'dateIn': since,
                'dateOut': to,
                'organizationId': self.lockself_organization_id,
                'limit': limit
            }
            offset = 1
            logs = []
            result = self.execute_query(url, params=query)
            logs.extend(result["_embedded"]["items"])

            while len(logs) < int(result["total"]):
                offset += limit
                query["offset"] = offset
                self.update_lock()
                result = self.execute_query(url, params=query)
                logs.extend(result["_embedded"]["items"])

            return logs

    def test(self):
        try:
            logs = self.get_logs(timezone.now()-timedelta(days=1), timezone.now())
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

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        since = self.frontend.last_api_call or (timezone.now() - timedelta(hours=24))
        to = min(timezone.now(), since + timedelta(hours=24))
        # Delay the query of 5 minutes to avoid missing logs
        to = to - timedelta(minutes=5)
        logs = self.get_logs(since, to)
        # Downloading may take some while, so refresh token in Redis
        self.update_lock()
        self.write_to_file([self.format_log(log) for log in logs])
        # Writting may take some while, so refresh token in Redis
        self.update_lock()
        # increment by 1s to avoid duplication of logs
        self.frontend.last_api_call = to + timedelta(seconds=1)
        self.frontend.save(update_fields=['last_api_call'])
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})