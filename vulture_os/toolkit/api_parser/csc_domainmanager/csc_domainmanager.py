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

from datetime import datetime, timedelta

import logging
import json

from copy import deepcopy
from requests import Session

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

    def get_logs(self, since: datetime, to: datetime, page: int, timeout=10) -> (dict, Exception):
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

            logger.info(f"[{__parser__}]:execute_query: URL: {url} , params: {params}", extra={'frontend': str(self.frontend)})
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

            logger.info(f"{[__parser__]}:execute: Collect logs since {since} to {to}",
                        extra={'frontend': str(self.frontend)})

            while logs := self.get_logs(page=page, since=since, to=to):
                if 'events' not in logs:
                    break

                self.update_lock()

                #Splitting of logs with several records
                """For example :
                    "records": {
                    "a": [
                        {
                        "action": "PURGE",
                        "key": "indicedeperformancesociale",
                        "value": "109.2.147.92",
                        "previousKey": "indicedeperformancesociale",
                        "previousValue": "109.2.147.92",
                        "ttl": null,
                        "previousTtl": null
                        }
                    ],
                    "cname": [
                        {
                        "action": "ADD",
                        "key": "indicedeperformancesociale",
                        "value": "swyavfi.impervadns.net.",
                        "previousKey": null,
                        "previousValue": null,
                        "ttl": null,
                        "previousTtl": null
                        },
                        {
                        "action": "ADD",
                        "key": "toto",
                        "value": "toto.toto.net.",
                        "previousKey": null,
                        "previousValue": null,
                        "ttl": null,
                        "previousTtl": null
                        }
                    ]
                    }
                    Is splitted in 3 logs :
                    "records": {
                    "a":
                        {
                        "action": "PURGE",
                        "key": "indicedeperformancesociale",
                        "value": "109.2.147.92",
                        "previousKey": "indicedeperformancesociale",
                        "previousValue": "109.2.147.92",
                        "ttl": null,
                        "previousTtl": null
                        }
                    }
                    "records": {
                    "cname":
                        {
                        "action": "ADD",
                        "key": "indicedeperformancesociale",
                        "value": "swyavfi.impervadns.net.",
                        "previousKey": null,
                        "previousValue": null,
                        "ttl": null,
                        "previousTtl": null
                        },
                    }
                    "records": {
                    "cname":
                        {
                        "action": "ADD",
                        "key": "toto",
                        "value": "toto.toto.net.",
                        "previousKey": null,
                        "previousValue": null,
                        "ttl": null,
                        "previousTtl": null
                        }
                    }
                """
                split_logs = []
                for log in logs['events']:
                    if 'records' in log.get('event', []):
                        for record_key, record_values in log['event']['records'].items():
                            for record in record_values:
                                split_log = deepcopy(log)
                                split_log['event']['records'] = {record_key : deepcopy(record)}
                                split_logs.append(split_log)
                    else:
                        split_logs.append(log)

                self.write_to_file([json.dumps(log) for log in split_logs])

                self.update_lock()

                if logs['links'].get('next'):
                    page = page + 1
                    self.session = None
                else:
                    break

            self.frontend.last_api_call = to
            self.frontend.save()

            self.session = None

            logger.info(f"[{__parser__}]:execute: Parsing done", extra={'frontend': str(self.frontend)})

        except Exception as e:
            logger.error(f"[{__parser__}]:execute: Could not get results from logs -- {e}",
                         extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)
