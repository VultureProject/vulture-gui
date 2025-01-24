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
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'INFOBLOX THREAT DEFENSE API'
__parser__ = 'INFOBLOX_THREAT_DEFENSE'

import json
import logging

import dateutil
import requests

from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class InfobloxThreatDefenseAPIError(Exception):
    pass

class InfobloxThreatDefenseParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.infoblox_threat_defense_host = data["infoblox_threat_defense_host"].rstrip("/")
        if not self.infoblox_threat_defense_host.startswith('https://'):
            self.infoblox_threat_defense_host = f"https://{self.infoblox_threat_defense_host}"

        self.infoblox_threat_defense_token = data["infoblox_threat_defense_token"]
        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                self.session.headers.update(self.HEADERS)
                self.session.headers.update({"AUTHORIZATION": f"TOKEN {self.infoblox_threat_defense_token}"})
            return True

        except Exception as err:
            raise InfobloxThreatDefenseAPIError(err)

    def execute_query(self, url, params={}, timeout=20):

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies,
            timeout=timeout,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != 200:
            error = f"Error at Infoblox_Threat_Defense API Call: status : {response.status_code}, content : {response.content}"
            logger.error(f"[{__parser__}]:execute_query: {error}", extra={'frontend': str(self.frontend)})
            raise InfobloxThreatDefenseAPIError(error)

        return response.json()

    def get_logs(self, since, to, offset=0):
        self._connect()
        url = f"{self.infoblox_threat_defense_host}/api/dnsdata/v2/dns_event"

        params = {
            "t0": int(since.timestamp()),
            "t1": int(to.timestamp()),
            "_offset": offset,
            "_limit": 5000
        }
        response = self.execute_query(url, params=params)

        if response["status_code"] == "200" and response["result"]:
            return response["result"]
        elif response["status_code"] != "200":
            error = f"Error at Infoblox_Threat_Defense API Call: API returns a {response.get('status_code')} status code in its JSON content"
            logger.error(f"[{__parser__}]:get_logs: {error}", extra={'frontend': str(self.frontend)})
            raise InfobloxThreatDefenseAPIError(error)


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

    def format_log(self, log, since, to):
        return json.dumps(log)

    def execute(self):
        since = self.last_api_call or (timezone.now() - timedelta(days=30))
        to = min(timezone.now(), since + timedelta(hours=24))

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        offset = 0
        while not self.evt_stop.is_set():

            logs = self.get_logs(since, to, offset)

            if not logs:
                break

            offset += len(logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            self.write_to_file([self.format_log(l, since, to) for l in logs])

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        # increment by 1s to avoid duplication of logs
        self.frontend.last_api_call = to + timedelta(seconds=1)
        self.frontend.save()
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})