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
__author__ = "gparain"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Trendmicro Visionone API Parser'
__parser__ = 'TRENDMICRO VISIONONE'

import json
import logging
import requests

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import dateparse, timezone

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')



class TrendmicroVisionOneAPIError(Exception):
    pass


class TrendmicroVisiononeParser(ApiParser):
    URL_BASE = "https://api.eu.xdr.trendmicro.com"

    def __init__(self, data):
        """
            trendmicro_visionone_token

        """
        super().__init__(data)

        self.trendmicro_visionone_token = data["trendmicro_visionone_token"]


    def _get_alerts(self, since=None, to=None):

        url_path = '/v3.0/workbench/alerts'

        query_params = {'startDateTime': since,
                        'endDateTime': to,
                        'dateTimeTarget': 'createdDateTime',
                        'orderBy': 'createdDateTime desc'}
        headers = {'Authorization': 'Bearer ' + self.trendmicro_visionone_token, 'TMV1-Filter': ""}

        result = requests.get(self.URL_BASE + url_path, params=query_params, headers=headers)
        if result.status_code != 200:
            raise TrendmicroVisionOneAPIError(
                f"Error on URL: {self.URL_BASE + url_path} Status: {result.status_code} Reason/Content: {result.content}")

        return result.json()['items']

    def _get_auditlogs(self, since=None, to=None):
        url_path = '/v3.0/audit/logs'

        query_params = {'startDateTime': since,
                        'endDateTime': to,
                        'orderBy': 'createdDateTime desc',
                        'top': 50,
                        'labels': 'all'}
        headers = {'Authorization': 'Bearer ' + self.trendmicro_visionone_token,
                   'Accept': 'application/json',
                   'TMV1-Filter': ''}

        r = requests.get(self.URL_BASE + url_path, params=query_params, headers=headers)

        if r.status_code != 200:
            raise TrendmicroVisionOneAPIError(
                f"Error on URL: {self.URL_BASE + url_path} Status: {r.status_code} Reason/Content: {r.content}")

        return r.json()['items']

    def _get_OAT(self, since=None, to=None):

        url_path = '/v3.0/audit/logs'

        query_params = {'detectedStartDateTime': since,
                        'detectedEndDateTime': to,
                        'ingestedStartDateTime': since,
                        'ingestedEndDateTime': to,
                        'top': 50}
        headers = {'Authorization': 'Bearer ' + self.trendmicro_visionone_token,
                   'Accept': 'application/json',
                   'TMV1-Filter': ''}

        r = requests.get(self.URL_BASE + url_path, params=query_params, headers=headers)

        if r.status_code != 200:
            raise TrendmicroVisionOneAPIError(
                f"Error on URL: {self.URL_BASE + url_path} Status: {r.status_code} Reason/Content: {r.content}")

        return r.json()['items']

    def _format_OAT_log(self, log):
        return log["detail"]


    def execute(self):

        since = self.frontend.last_api_call or (timezone.now() - timedelta(hours=1))
        to = timezone.now()
        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
        start_time = since.isoformat().replace("+00:00", "Z")
        end_time = to.isoformat().replace("+00:00", "Z")

        result = self._get_alerts(start_time, end_time)

        self.write_to_file(result)

        result = self._get_auditlogs(start_time, end_time)

        self.write_to_file(result)

        result = self._get_OAT(start_time, end_time)

        self.write_to_file(self._format_OAT_log(result))

        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        self.frontend.last_api_call = to
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})


    def test(self):

        since = timezone.now() - timedelta(hours=1)
        to = timezone.now()
        logs = {}
        start_time = since.isoformat().replace("+00:00", "Z")
        end_time = to.isoformat().replace("+00:00", "Z")

        try:
            alerts = self._get_alerts(start_time, end_time)
            auditlogs = self._get_auditlogs(start_time, end_time)
            detection_logs = self._get_OAT(since, to)

            return {
                "status": True,
                "data": (alerts + auditlogs + detection_logs)
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
