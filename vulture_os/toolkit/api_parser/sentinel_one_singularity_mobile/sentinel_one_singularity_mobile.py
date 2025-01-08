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
__author__ = ""
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Sentinel One Mobile Zimperium API Parser toolkit'
__parser__ = 'SENTINEL ONE MOBILE ZIMPERIUM'



import requests
import json
import logging

import datetime
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SentinelOneSingularityMobileParser(ApiParser):
    HEADERS = {
        "Accept": "application/json"
    }
    SIZE = 2000

    def __init__(self, data):
        super().__init__(data)

        self.__access_token = ""
        self.session = None

        self.host = data["sentinel_one_singularity_mobile_host"]
        self.client_id = data["sentinel_one_singularity_mobile_client_id"]
        self.__secret = data["sentinel_one_singularity_mobile_client_secret"]

    def get_access_token(self):
        if not self.__access_token:
            try:
                url = f"https://{self.host}/api/auth/v1/api_keys/login"
                data = {
                    "clientId": self.client_id,
                    "secret": self.__secret,
                }
                response = requests.post(url, json=data, headers=self.HEADERS)
                response.raise_for_status()
            except requests.exceptions.HTTPError as err:
                logger.debug(err, extra={'frontend': str(self.frontend)})
                exit(0)
            else:
                response_json = response.json()
                self.__access_token = response_json["accessToken"]
        return self.__access_token

    def _connect(self):
        if self.session is None:
            self.session = requests.Session()
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Bearer {self.get_access_token()}"})
        return True

    def get_logs(self, since, to):
        if self.session is None:
            self._connect()

        def convert(x): return x.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
        url = f"https://{self.host}/api/threats/public/v1/threats"

        params = {
            "page": 0,
            "size": self.SIZE,
            "after": convert(since),  # >=
            "before": convert(to),    # <=
            "sort": "timestamp,asc",
            "module": "ZIPS"
        }

        response = self.session.get(url, params=params)

        resp = response.json()
        logger.debug(f"url: {url}\nparams: {params}", extra={'frontend': str(self.frontend)})

        if "content" not in resp:
            raise Exception(str(resp))
        return resp['content']

    def test(self):
        logger.info(f"[{__parser__}]:test: launching test query (getting logs from 10 days ago)",
                    extra={'frontend': str(self.frontend)})

        to = timezone.now()
        since = to - datetime.timedelta(days=10)

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
        since = self.last_api_call or (datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=24))
        to = datetime.datetime.now(tz=datetime.timezone.utc)
        logger.debug(f'since: {since}\n to: {to}\n', extra={'frontend': str(self.frontend)})

        while since < to:
            logs = self.get_logs(since, to)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            found = len(logs)
            logger.debug(f"found: {found}", extra={'frontend': str(self.frontend)})

            if found == 0:
                break

            self.write_to_file([json.dumps(log) for log in logs])

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            last_time = datetime.datetime.fromtimestamp(logs[-1]['timestamp'] // 1000, tz=datetime.timezone.utc)
            since = last_time + datetime.timedelta(milliseconds=1)
            self.frontend.last_api_call = since

            logger.debug(f'frontend last_api_call: {self.frontend.last_api_call}', extra={'frontend': str(self.frontend)})
            logger.debug(last_time, extra={'frontend': str(self.frontend)})

            if found < self.SIZE:
                break

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
