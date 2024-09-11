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
__credits__ = ["Florian Ledoux", "Antoine Lucas", "Julien Pollet", "Nicolas Lançon"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cybereason API Parser toolkit'
__parser__ = 'CYBEREASON'

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone

import json
import logging
from datetime import timedelta
import requests
import time

from toolkit.api_parser.cybereason.malop import Malop
from toolkit.api_parser.cybereason.malware import Malware

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class CybereasonAPIError(Exception):
    pass


class CybereasonParser(ApiParser):

    LOGIN_URI = "login.html"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data: dict) -> None:
        super().__init__(data)

        self.host = data["cybereason_host"]
        self.username = data["cybereason_username"]
        self.password = data["cybereason_password"]
        # Remove last "/" if present
        if self.host[-1] == '/':
            self.host = self.host[:-1]

        # Remove scheme for observer
        if "://" not in self.host:
            self.observer_name = self.host
            self.host = f"https://{self.host}"
        else:
            self.observer_name = self.host.split("://")[1]

        self.session = None

        self.log_types = {
            "malops": Malop(self),
            "malwares": Malware(self),
        }

    def _connect(self) -> bool:
        try:
            if self.session is None:
                self.session = requests.Session()

                login_url = f"{self.host}/{self.LOGIN_URI}"

                auth = {
                    "username": self.username,
                    "password": self.password
                }

                response = self.session.post(
                    login_url,
                    data=auth,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                )
                response.raise_for_status()
                if "app-login" in response.content.decode('utf-8'):
                    raise CybereasonAPIError(f"Authentication failed on {login_url} for user {self.username}")
                logger.info(f"[{__parser__}]:_connect: Successfully logged-in",
                            extra={'frontend': str(self.frontend)})
            return True

        except Exception as err:
            raise CybereasonAPIError(err)

    def execute_query(self, method: str, url: str, query: dict=None, header: dict=HEADERS, data: str=None, sleepretry: int=10, timeout: int=10) -> dict:
        self._connect()

        response = None
        retry = 0
        while retry < 3:
            retry += 1
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=query,
                    headers=header,
                    data=data,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl,
                    timeout=timeout
                )
            except requests.exceptions.ReadTimeout:
                msg = f"ReadTimeout, waiting {sleepretry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleepretry)
                continue
            except requests.exceptions.ConnectionError:
                msg = f"ConnectionError, waiting {sleepretry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleepretry)
                continue
            if response.status_code != 200:
                msg = f"Status Code {response.status_code}, waiting {sleepretry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleepretry)
                continue
            break  # no error we break from the loop

        if response is None:
            msg = f"Error Cybereason API Call URL: {url} [TIMEOUT]"
            logger.error(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
            return {}
        elif response.status_code != 200:
            msg = f"Error Cybereason API Call URL: {url} [TIMEOUT], Code: {response.status_code}"
            logger.error(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
            return {}

        return json.loads(response.content)

    def test(self) -> dict:
        try:
            # Get logs from last 2 days
            to = timezone.now()
            since = (to - timedelta(hours=24))

            all_logs = []
            for log_type, related_class in self.log_types.items():
                logs, _, _ = related_class.get_logs(since, to)
                all_logs.extend(logs)

            msg = f"{len(all_logs)} alert(s) retrieved"
            logger.info(f"[{__parser__}]:test: {msg}", extra={'frontend': str(self.frontend)})

            return {
                "status": True,
                "data": json.dumps(all_logs)
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since: object, to: object) -> None:
        # this method is replaced in related class
        pass

    def add_enrichment(self, log: dict) -> None:
        # this method is replaced in related class
        pass

    def format_log(self, log: dict) -> None:
        # this method is replaced in related class
        pass

    def execute(self) -> None:

        for log_type, related_class in self.log_types.items():
            # Get last api call or 30 days ago
            since = self.last_collected_timestamps.get(f"cybereason_{log_type}") or (timezone.now() - timedelta(days=30))
            # 24h max per request

            to = min(timezone.now(), since + timedelta(hours=24))
            # to = timezone.now()

            # delay the times of 5 minutes, to let the times at the API to have all logs
            to = to - timedelta(minutes=5)

            has_more_logs = True
            while has_more_logs:

                msg = f"Parser starting with {log_type} from {since} to {to}"
                logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                # Get bulk of 1000 logs, the last log's timestamp and if more logs are available
                logs, last_timestamp, has_more_logs = related_class.get_logs(since, to)

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                enriched_logs = [
                    related_class.format_log(related_class.add_enrichment(log))
                    for log in logs
                ]

                # Enriching may take some while, so refresh token in Redis
                self.update_lock()

                self.write_to_file(enriched_logs)

                # Writting may take some while, so refresh token in Redis
                self.update_lock()

                if len(logs) > 0:
                    # update last_api_call only if logs are retrieved
                    if has_more_logs and last_timestamp:
                        self.last_collected_timestamps[f"cybereason_{log_type}"] = last_timestamp
                    else:
                        self.last_collected_timestamps[f"cybereason_{log_type}"] = to

                    # if more logs are available, reset since var for the next iter
                    since = self.last_collected_timestamps[f"cybereason_{log_type}"]

                elif len(logs) == 0 and since < timezone.now() - timedelta(hours=24):
                    # If no logs where retrieved during the last 24hours,
                    # move forward 1h to prevent stagnate ad vitam eternam
                    self.last_collected_timestamps[f"cybereason_{log_type}"] = since + timedelta(hours=1)
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
