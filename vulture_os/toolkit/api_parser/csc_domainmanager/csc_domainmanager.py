#!venv/bin/python
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
from dateutil.parser import parse as date_parse

from os import path, remove
from sys import path as sys_path
import logging

from requests import Session as requests_session
from urllib.parse import quote,unquote

from django.conf import settings

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

        if self.last_api_call and isinstance(self.last_api_call, str):
            self.last_api_call = date_parse(self.last_api_call)

        if self.csc_domainmanager_authorization and not self.csc_domainmanager_authorization.startswith("Bearer "):
            self.csc_domainmanager_authorization = f"Bearer {self.csc_domainmanager_authorization}"

        self.session = None


    def _connect(self):
        """
        Create session & prepare headers
        """
        try:
            if (self.session is None):
                self.session = requests_session()

                self.session.headers['apikey'] = self.csc_domainmanager_apikey
                self.session.headers['Authorization'] = self.csc_domainmanager_authorization

                return True

        except Exception as e:
            logger.error(f"[{__parser__}]:connect: Exception while creating session -- {e}", extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)

    def get_logs(self, since, page=1, timeout=10) -> list: #to
        """
        Send a query to csc domainmanager api to get logs
        """
        try:
            self._connect()

            params = {
                "size": 1,
                "page": page,
                "filter": f"eventDate=ge={since}",
                "sort": "eventDate,asc"
            }

            url = "https://apis.cscglobal.com/dbs/api/v2/events"

            r = self.session.get(url, params=params, headers=self.HEADERS, proxies=self.proxies, stream=False, timeout=timeout)

            if r.status_code != 200:
                raise CscDomainManagerAPIError(f"Error on URL: {url} Status: {r.status_code} Reason/Content: {r.content}")

            try:
                return r.json()
            except Exception as e:
                logger.error(f"[{__parser__}]:get_logs: Bad json formatting -- {e}", extra={'frontend': str(self.frontend)})
                raise CscDomainManagerAPIError(f"Error while formatting json -- {e}")

        except Exception as e:
            logger.error(f"[{__parser__}]:get_logs: Exception while getting logs on {url} -- {e}", extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)


    def _format_log(self, log:dict) -> dict:
        """
        Format input log
        """
        try:
            timestamp = datetime.strptime(log['event'].get('date'),"%Y-%m-%dT%H:%M:%SZ").timestamp()
            if self.last_log_time < timestamp:
                self.last_log_time = timestamp
        except Exception as e:
            logger.error(f"[{__parser__}]:format_log: Exception while updating last_log_time logs -- {e}", extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)
        try:
            return dumps(log)
        except Exception as e:
            logger.error(f"[{__parser__}]:format_log: Bad json formatting -- {e}", extra={'frontend': str(self.frontend)})
            raise CscDomainManagerAPIError(e)

    def test(self):
        try:
            logs = self.get_logs(since=(datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S"))

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
            if self.last_api_call < datetime.now() - timedelta(hours=24):
                self.last_api_call += timedelta(hours=1)

            page = 1
            logs = self.get_logs(page=page, since=str(self.last_api_call).replace(" ","T"))
            self.update_lock()

            if not logs['links'].get('next') and logs['events'] and self.last_log_time != self.last_api_call.timestamp():
                self.write_to_file([self._format_log(event) for event in logs['events']])
                self.update_lock()
                if self.last_log_time != 0:
                    self.last_api_call = date_parse(datetime.fromtimestamp(self.last_log_time).isoformat())
                    self.update_conf_file(type_="last_api_call", last_api_call=self.last_api_call)

            elif logs['links'].get('next') and logs['events'] and self.last_log_time != self.last_api_call.timestamp():
                self.write_to_file([self._format_log(event) for event in logs['events']])
                self.update_lock()
                page = page + 1
                self.session = None
                lock = True
                while lock:
                    logs = self.get_logs(page=page, since=str(self.last_api_call).replace(" ","T"))
                    self.update_lock()
                    self.write_to_file([self._format_log(event) for event in logs['events']])
                    self.update_lock()
                    page = page + 1
                    self.session = None

                    if logs['events'] and not logs['links'].get('next'):
                        lock = False

                if self.last_log_time != 0:
                    self.last_api_call = date_parse(datetime.fromtimestamp(self.last_log_time).isoformat())
                    self.update_conf_file(type_="last_api_call", last_api_call=self.last_api_call)

        self.session = None

        logger.info(f"[{__parser__}]:execute: Parsing done", extra={'frontend': str(self.frontend)})

        except Exception as e:
            logger.error(f"[{__parser__}]:execute: Could not get results from logs -- {e}", extra={'frontend': str(self.frontend)})
            CscDomainManagerAPIError(e)