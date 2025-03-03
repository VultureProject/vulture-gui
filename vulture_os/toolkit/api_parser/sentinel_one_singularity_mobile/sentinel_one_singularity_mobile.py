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
__author__ = "Dimitri Bischoff"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Sentinel One Singularity Mobile API Parser toolkit'
__parser__ = 'SENTINEL ONE SINGULARITY MOBILE'



import requests
import json
import logging
import time

from datetime import timedelta, datetime
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SentinelOneSingularityMobileError(Exception):
    ...


class SentinelOneSingularityMobileParser(ApiParser):
    HEADERS = {
        "Accept": "application/json"
    }
    SIZE = 2000

    def __init__(self, data):
        super().__init__(data)

        self.session = None

        self.host = data["sentinel_one_singularity_mobile_host"]
        self.client_id = data["sentinel_one_singularity_mobile_client_id"]
        self.__secret = data["sentinel_one_singularity_mobile_client_secret"]

        self.access_token = data.get("sentinel_one_singularity_mobile_access_token", None)
        self.expires_on = data.get("sentinel_one_singularity_mobile_access_token_expiry", None)

    def _reinit_token(self):
        if self.frontend:
            self.frontend.sentinel_one_singularity_mobile_access_token_expiry = None
            self.frontend.sentinel_one_singularity_mobile_access_token = None
            self.frontend.save()

    def _save_token(self):
        if self.frontend:
            self.frontend.sentinel_one_singularity_mobile_access_token_expiry = self.expires_on
            self.frontend.sentinel_one_singularity_mobile_access_token = self.access_token
            self.frontend.save()

    def get_access_token(self):
        if not self.expires_on or not self.access_token or timezone.now() > self.expires_on:
            self._reinit_token()
            try:
                url = f"https://{self.host}/api/auth/v1/api_keys/login"
                data = {
                    "clientId": self.client_id,
                    "secret": self.__secret,
                }
                response = requests.post(
                    url,
                    json=data,
                    headers=self.HEADERS,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)
                response.raise_for_status()
            except requests.exceptions.HTTPError as err:
                logger.error(f"{[__parser__]}:get_access_token: {err}", extra={'frontend': str(self.frontend)})
                raise err
            else:
                self.access_token = response.json()["accessToken"]
                self.expires_on = timezone.now() + timedelta(minutes=50)
                self._save_token()
        return self.access_token

    def _connect(self):
        if self.session is None:
            self.session = requests.Session()
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Bearer {self.get_access_token()}"})
        return True

    def get_logs(self, since, to):
        if self.session is None:
            self._connect()

        def format_timestamp(x): return x.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
        url = f"https://{self.host}/api/threats/public/v1/threats"

        params = {
            "page": 0,
            "size": self.SIZE,
            "after": format_timestamp(since),  # >=
            "before": format_timestamp(to),    # <=
            "sort": "timestamp,asc",
            "module": "ZIPS"
        }
        logger.info(f"{[__parser__]}:get_logs: url: {url}, params: {params}", extra={'frontend': str(self.frontend)})

        response = self.session.get(url,
            params=params,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)

        if response.status_code != 200:
            self._reinit_token()
            raise SentinelOneSingularityMobileError(f"Error on URL: {url} Status: {response.status_code} Reason/Content: {response.content}")

        return response.json()['content']

    def test(self):
        logger.info(f"[{__parser__}]:test: launching test query (getting logs from 10 days ago)",
                    extra={'frontend': str(self.frontend)})

        to = timezone.now()
        since = to - timedelta(days=10)

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
        since = self.last_api_call or (timezone.now() - timedelta(hours=24))
        to = min(timezone.now(), since + timedelta(hours=24))
        logger.info(f'[{__parser__}]:execute: Getting logs from {since} to {to}',
                    extra={'frontend': str(self.frontend)})

        while since < to and not self.evt_stop.is_set():
            logs = self.get_logs(since, to)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            found = len(logs)
            logger.info(f'[{__parser__}]:execute: Got {found} new logs', extra={'frontend': str(self.frontend)})

            self.write_to_file([json.dumps(log) for log in logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            if found > 0:
                last_time = datetime.fromtimestamp(logs[-1]['timestamp'] // 1000, tz=timezone.utc)
                since = last_time + timedelta(milliseconds=1)
                self.frontend.last_api_call = since
            elif self.last_api_call < (timezone.now() - timedelta(hours=24)):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                self.frontend.last_api_call += timedelta(hours=1)
                logger.info(f"[{__parser__}]:execute: No recent alert found and last_api_call too old - "
                            f"setting it to {self.frontend.last_api_call}",
                            extra={'frontend': str(self.frontend)})
                break
            else:
                since = to
                self.frontend.last_api_call = since

            logger.info(f'[{__parser__}]:execute: frontend last_api_call: {self.frontend.last_api_call}', extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
