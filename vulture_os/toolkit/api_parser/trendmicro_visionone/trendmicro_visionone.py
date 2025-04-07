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

from datetime import timedelta
from django.conf import settings
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

MAX_TOTAL_COUNT = 10000
MIN_QUERY_INTERVAL = 1  # seconds


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

    def __execute_query(self, kind, since, to, timeout=30):

        items = []
        status = False

        headers = {'Authorization': 'Bearer ' + self.trendmicro_visionone_token, 'TMV1-Filter': ""}
        max_retries = 3
        retry = max_retries

        query = {}
        url_path = ""
        link = ""
        has_next = False

        while not status and retry > 0 and not self.evt_stop.is_set():
            self.update_lock()
            try:
                if not has_next:
                    # We have to do this only if we're not using the next link
                    if kind == "alerts":
                        query, url_path = self._prepare_request_alerts(since, to)
                    elif kind == "audit":
                        query, url_path = self._prepare_request_auditlogs(since, to)
                    elif kind == "oat":
                        query, url_path = self._prepare_request_OAT(since, to)
                        headers.update({'TMV1-Filter': "not (riskLevel eq 'info')"})

                    link = self.URL_BASE + url_path

                logger.info(f"[{__parser__}]:__execute_query: URL: {link} , params: {query}", extra={'frontend': str(self.frontend)})
                r = requests.get(link, params=query, headers=headers,proxies=self.proxies, verify=self.api_parser_verify_ssl, timeout=timeout)
                if r.status_code != 200:
                    status = False
                    logger.error(f"Error on URL: {link} Status: {r.status_code} Reason/Content: {r.content}")
                    raise TrendmicroVisionOneAPIError(f"Error on URL: {link} Status: {r.status_code} Reason/Content: {r.content}")

                request_json = r.json()
                if kind != "audit" and request_json.get('totalCount') >= MAX_TOTAL_COUNT:
                    # Note : This attribute is not present in audit logs response
                    raise requests.exceptions.ReadTimeout(f"Total count = {request_json.get('totalCount')} > {MAX_TOTAL_COUNT} (given max count)")

                items.extend(request_json['items'])

                if link := request_json.get('nextLink'):
                    query = None
                    has_next = True
                else:
                    has_next = False
                    status = True
            except requests.exceptions.ReadTimeout as e:
                logger.exception(f"[{__parser__}]:__execute_query: {e}", extra={'frontend': str(self.frontend)})
                has_next = False
                to -= (to - since) / 2
                if (to - since) < timedelta(seconds=MIN_QUERY_INTERVAL):
                    logger.error(
                        f"[{__parser__}]:__execute_query: Failed on {kind} logs, time range too small between {since} and {to}",
                        extra={'frontend': str(self.frontend)})
                    break
                else:
                    logger.info(
                        f"[{__parser__}]:__execute_query: Will retry with smaller time range : {since} to {to}",
                        extra={'frontend': str(self.frontend)})

            except Exception as e:
                logger.error(f"[{__parser__}]:execute: Failed on {kind} logs, between time of {since} and {to} : {e}",
                             extra={'frontend': str(self.frontend)})
                logger.exception(f"[{__parser__}]:__execute_query: {e}", extra={'frontend': str(self.frontend)})
                retry -= 1

        if not status and retry <= 0:
            logger.error(f"[{__parser__}]:execute: Failed on {kind} logs, max of {max_retries} retries exceeded",
                         extra={'frontend': str(self.frontend)})

        return items, status, since, to

    def _prepare_request_alerts(self, since=None, to=None):
        url_path = '/v3.0/workbench/alerts'
        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            'startDateTime': start_time,
            'endDateTime': end_time,
            'dateTimeTarget': 'createdDateTime',
            'orderBy': 'createdDateTime desc',
            'top': 200
        }

        return query, url_path

    def _prepare_request_auditlogs(self, since=None, to=None):
        url_path = '/v3.0/audit/logs'
        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            'startDateTime': start_time,
            'endDateTime': end_time,
            'orderBy': 'createdDateTime desc',
            'labels': 'all',
            'top': 200
        }

        return query, url_path

    def _prepare_request_OAT(self, since=None, to=None):
        url_path = '/v3.0/oat/detections'
        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")
        query = {
            'detectedStartDateTime': start_time,
            'detectedEndDateTime': end_time,
            'top': 10000
        }

        return query, url_path
    
    @staticmethod
    def _format_logs(log):
        return json.dumps(log)

    def execute(self):
        for kind in ["alerts", "oat", "audit"]:

            since = getattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp") or (
                        timezone.now() - timedelta(days=2))
            to = min(timezone.now() - timedelta(minutes=5), since + timedelta(hours=24))

            while to <= timezone.now() - timedelta(minutes=5) and not self.evt_stop.is_set():
                logger.info(f"[{__parser__}]:execute: Parser gets {kind} logs from {since} to {to}", extra={'frontend': str(self.frontend)})

                self.update_lock()
                logs, status, since, to = self.__execute_query(kind, since, to)

                if status:
                    self.write_to_file([self._format_logs(log) for log in logs])
                    self.update_lock()
                    total = len(logs)
                    current_kind_timestamp = getattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp")
                    if total > 0:
                        setattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp", to)
                    elif current_kind_timestamp < timezone.now() - timedelta(hours=24):
                        # If no logs where retrieved during the last 24hours,
                        # move forward 1h to prevent stagnate ad vitam eternam
                        setattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp", current_kind_timestamp + timedelta(hours=1))

                    last_time_range = to - since
                    since = to
                    to += last_time_range
                    self.frontend.save()
                else:
                    logger.error(
                        f"[{__parser__}]:execute: Failed on {kind} logs, error status received",
                        extra={'frontend': str(self.frontend)})
                    break

            else:
                logger.info(
                    f"[{__parser__}]:execute: Log collection for {kind}'s logs stopped at {getattr(self.frontend, f'trendmicro_visionone_{kind}_timestamp')}",
                    extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

    def test(self):
        since = timezone.now() - timedelta(hours=24)
        to = timezone.now()
        start_time = since
        start_time_oat = since + timedelta(hours=23, minutes=59)
        end_time = to
        auditlogs = list()
        detection_logs = list()

        try:
            alerts, status, _, _ = self.__execute_query("alerts", start_time, end_time)
            if status:
                auditlogs, status, _, _ = self.__execute_query("audit", start_time, end_time)
            if status:
                detection_logs, status, _, _ = self.__execute_query("oat", start_time_oat, end_time)

            return {
                "status": status,
                "data": ([self._format_logs(log) for log in alerts] + [self._format_logs(log) for log in auditlogs] + [self._format_logs(log) for log in detection_logs])
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
