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
__author__ = "Maël Bonniot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "1.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'CSC DOMAINMANAGER API'
__parser__ = 'CSC DOMAINMANAGER'

import json
from datetime import datetime, timedelta

import logging

from requests import Session

from json import dumps

from django.conf import settings
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CscDomainManagerAPIError(Exception):
    pass


class CscDomainManagerParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.csc_domainmanager_apikey = data.get("csc_domainmanager_apikey")
        self.csc_domainmanager_authorization = data.get("csc_domainmanager_authorization")

        self.last_log_time = 0

        if self.csc_domainmanager_authorization and not self.csc_domainmanager_authorization.startswith("Bearer "):
            self.csc_domainmanager_authorization = f"Bearer {self.csc_domainmanager_authorization}"

        self.session = None

    def _connect(self) -> (bool, Exception):
        """
        Create session & prepare headers
        """
        try:
            if self.session is None:
                self.session = Session()

                self.session.headers['apikey'] = self.csc_domainmanager_apikey
                self.session.headers['Authorization'] = self.csc_domainmanager_authorization

                return True

        except Exception as e:
            logger.error(f"[{__parser__}]:connect: Exception while creating session -- {e}",
                         extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)

    def get_logs(self, since: datetime, to: datetime, page: int, timeout=10) -> dict:
        """
        Send a query to csc domainmanager api to get logs
        """
        try:
            self._connect()

            params = {
                "size": 1000,
                "page": page,
                "filter": f"eventDate=gt={since.isoformat().replace(' ', 'T')};eventDate=le={to.isoformat().replace(' ', 'T')}",
                "sort": "eventDate,asc"
            }

            url = "https://apis.cscglobal.com/dbs/api/v2/events"

            r = self.session.get(
                url,
                params=params,
                headers=self.HEADERS,
                proxies=self.proxies,
                verify=self.api_parser_verify_ssl,
                stream=False,
                timeout=timeout
            )

            if r.status_code != 200:
                raise CscDomainManagerAPIError(
                    f"Error on URL: {url} Status: {r.status_code} Reason/Content: {r.content}")

            try:
                return r.json()
            except Exception as e:
                logger.error(f"[{__parser__}]:get_logs: Bad json formatting -- {e}",
                             extra={'frontend': str(self.frontend)})
                raise CscDomainManagerAPIError(f"Error while formatting json -- {e}")

        except Exception as e:
            logger.error(f"[{__parser__}]:get_logs: Exception while getting logs -- {e}",
                         extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)

    def update_last_log_time(self, log: dict) -> (None, Exception):
        """
        Update self.last_log_time
        """
        try:
            timestamp = datetime.strptime(log['event'].get('date'), "%Y-%m-%dT%H:%M:%SZ").timestamp()
            if self.last_log_time < timestamp:
                self.last_log_time = timestamp
        except Exception as e:
            logger.error(f"[{__parser__}]:format_log: Exception while updating last_log_time logs -- {e}",
                         extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)

    def test(self):
        try:
            page = 1
            since = timezone.now() - timedelta(hours=24)
            to = min(timezone.now(), since + timedelta(hours=24))

            logs = self.get_logs(page=page, since=since, to=to)

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

    def execute(self):
        """
        Central function to fetch logs
        """
        try:
            page = 1
            since = self.last_api_call or timezone.now() - timedelta(hours=24)
            to = min(timezone.now(), since + timedelta(hours=24))

            while logs := self.get_logs(page=page, since=since, to=to):
                if self.evt_stop.is_set() or not logs.get('events'):
                    break

                self.update_lock()

                # Update self.last_log_time
                for log in logs['events']:
                    self.update_last_log_time(log)

                self.write_to_file(logs['events'])

                self.update_lock()

                if self.last_log_time:
                    self.frontend.last_api_call = datetime.fromtimestamp(self.last_log_time, tz=timezone.utc)
                    self.frontend.save()

                if logs['links'].get('next'):
                    page = page + 1
                    self.session = None
                else:
                    break

            if self.last_api_call < timezone.now() - timedelta(hours=24):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                self.frontend.last_api_call += timedelta(hours=1)
                self.frontend.save()

            self.session = None

            logger.info(f"[{__parser__}]:execute: Parsing done", extra={'frontend': str(self.frontend)})

        except Exception as e:
            logger.error(f"[{__parser__}]:execute: Could not get results from logs -- {e}",
                         extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)
