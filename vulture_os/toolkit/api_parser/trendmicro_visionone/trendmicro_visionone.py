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
        self.trendmicro_visionone_alerts_timestamp = data.get("trendmicro_visionone_alerts_timestamp")
        self.trendmicro_visionone_audit_timestamp = data.get("trendmicro_visionone_audit_timestamp")
        self.trendmicro_visionone_oat_timestamp = data.get("trendmicro_visionone_oat_timestamp")

    def __execute_query(self, url_path, query, timeout=10):
        items = []

        headers = {'Authorization': 'Bearer ' + self.trendmicro_visionone_token, 'TMV1-Filter': ""}

        link = self.URL_BASE + url_path
        try:
            while True:
                r = requests.get(link, params=query, headers=headers,
                                 proxies=self.proxies, verify=self.api_parser_verify_ssl, timeout=timeout)
                if r.status_code != 200:
                    raise TrendmicroVisionOneAPIError(
                        f"Error on URL: {link} Status: {r.status_code} Reason/Content: {r.content}")

                items.extend(r.json()['items'])

                if link := r.json().get('nextLink'):
                    query = None
                    continue
                else:
                    break
        except Exception as e:
            logger.error(f"[{__parser__}]:__execute_query: Error on link '{link}' : {e}", extra={'frontend': str(self.frontend)})
        return items

    def _get_alerts(self, since=None, to=None):
        url_path = '/v3.0/workbench/alerts'

        query = {
            'startDateTime': since,
            'endDateTime': to,
            'dateTimeTarget': 'createdDateTime',
            'orderBy': 'createdDateTime desc'
        }

        alerts = self.__execute_query(url_path, query)

        return alerts

    def _get_auditlogs(self, since=None, to=None):
        url_path = '/v3.0/audit/logs'

        query = {
            'startDateTime': since,
            'endDateTime': to,
            'orderBy': 'createdDateTime desc',
            'labels': 'all'
        }

        auditlogs = self.__execute_query(url_path, query)

        return auditlogs

    def _get_OAT(self, since=None, to=None):
        url_path = '/v3.0/oat/detections'

        query = {
            'detectedStartDateTime': since,
            'detectedEndDateTime': to,
        }

        oat = self.__execute_query(url_path, query, timeout=30)

        return oat
    
    @staticmethod
    def _format_alert(log):
        return json.dumps(log)
    
    @staticmethod
    def _format_auditlog(log):
        return json.dumps(log)

    @staticmethod
    def _format_OAT_log(log):
        return json.dumps(log)

    def execute(self):
        for kind in ["alerts", "oat", "audit"]:

            try:
                since = getattr(self, f"trendmicro_visionone_{kind}_timestamp") or (timezone.now() - timedelta(days=2))
                to = min(timezone.now(), since + timedelta(hours=24))

                msg = f"Parser gets {kind} logs from {since} to {to}"
                logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
                end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")
                if kind == "alerts":
                    logs = self._get_alerts(start_time, end_time)
                    self.write_to_file([self._format_alert(log) for log in logs])
                elif kind == "audit":
                    logs = self._get_auditlogs(start_time, end_time)
                    self.write_to_file([self._format_auditlog(log) for log in logs])
                elif kind == "oat":
                    logs = self._get_OAT(start_time, end_time)
                    self.write_to_file([self._format_OAT_log(log) for log in logs])

                self.update_lock()
                setattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp", to)
                self.frontend.save()

            except Exception as e:
                msg = f"Failed on {kind} logs, between time of {since} and {to} : {e} "
                logger.error(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

    def test(self):
        since = timezone.now() - timedelta(hours=24)
        to = timezone.now()
        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            alerts = self._get_alerts(start_time, end_time)
            auditlogs = self._get_auditlogs(start_time, end_time)
            detection_logs = self._get_OAT(since, to)

            return {
                "status": True,
                "data": ([self._format_alert(log) for log in alerts] + [self._format_auditlog(log) for log in auditlogs] + [self._format_OAT_log(log) for log in detection_logs])
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
