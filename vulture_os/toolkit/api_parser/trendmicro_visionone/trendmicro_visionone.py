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
import time

from datetime import timedelta
from django.conf import settings
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

MAX_TOTAL_COUNT = 10000
MIN_QUERY_INTERVAL = 10  # seconds


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
        status = True

        headers = {'Authorization': 'Bearer ' + self.trendmicro_visionone_token, 'TMV1-Filter': ""}

        link = self.URL_BASE + url_path
        try:
            while True:
                logger.info(f"[{__parser__}]:__execute_query: URL: {link} , params: {query}", extra={'frontend': str(self.frontend)})
                r = requests.get(link, params=query, headers=headers,proxies=self.proxies, verify=self.api_parser_verify_ssl, timeout=timeout)
                if r.status_code != 200:
                    status = False
                    logger.error(f"Error on URL: {link} Status: {r.status_code} Reason/Content: {r.content}")
                    raise TrendmicroVisionOneAPIError(f"Error on URL: {link} Status: {r.status_code} Reason/Content: {r.content}")

                if r.json().get('totalCount') >= MAX_TOTAL_COUNT:
                    raise requests.exceptions.ReadTimeout(f"Total count = {r.json().get('totalCount')} > {MAX_TOTAL_COUNT} (given max count)")

                items.extend(r.json()['items'])

                if link := r.json().get('nextLink'):
                    query = None
                    self.update_lock()
                    continue
                else:
                    break
        except Exception as e:
            status = False
            logger.error(f"[{__parser__}]:__execute_query: Error on link '{link}' : {e}", extra={'frontend': str(self.frontend)})

        return items, status

    def _get_alerts(self, since=None, to=None):
        url_path = '/v3.0/workbench/alerts'
        query = {
            'startDateTime': since,
            'endDateTime': to,
            'dateTimeTarget': 'createdDateTime',
            'orderBy': 'createdDateTime desc',
            'top': 200
        }

        alerts, status = self.__execute_query(url_path, query)

        return alerts, status

    def _get_auditlogs(self, since=None, to=None):
        url_path = '/v3.0/audit/logs'
        query = {
            'startDateTime': since,
            'endDateTime': to,
            'orderBy': 'createdDateTime desc',
            'labels': 'all',
            'top': 200
        }

        auditlogs, status = self.__execute_query(url_path, query)

        return auditlogs, status

    def _get_OAT(self, since=None, to=None):
        url_path = '/v3.0/oat/detections'
        query = {
            'detectedStartDateTime': since,
            'detectedEndDateTime': to,
            'top': 5000
        }

        oat, status = self.__execute_query(url_path, query, timeout=30)

        return oat, status
    
    @staticmethod
    def _format_logs(log):
        return json.dumps(log)

    def execute(self):
        for kind in ["alerts", "oat", "audit"]:
            max_retries = 3
            retry = max_retries
            sleep_retry = 0.5
            success = False

            since = getattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp") or (
                        timezone.now() - timedelta(days=2))
            to = since + timedelta(minutes=1)

            while not success and retry > 0 and not self.evt_stop.is_set():
                try:
                    if retry < max_retries:
                        # That means this is not the first time and we are retrying -> waiting
                        logger.info(f"[{__parser__}]:execute: Will retry..", extra={'frontend': str(self.frontend)})
                        time.sleep(sleep_retry)

                    while to <= timezone.now() - timedelta(minutes=5) and not self.evt_stop.is_set():
                        logger.info(f"[{__parser__}]:execute: Parser gets {kind} logs from {since} to {to}", extra={'frontend': str(self.frontend)})
                        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
                        end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")

                        self.update_lock()
                        if kind == "alerts":
                            logs, status = self._get_alerts(start_time, end_time)
                        elif kind == "audit":
                            logs, status = self._get_auditlogs(start_time, end_time)
                        elif kind == "oat":
                            logs, status = self._get_OAT(start_time, end_time)

                        if status:
                            self.write_to_file([self._format_logs(log) for log in logs])
                            self.update_lock()
                            setattr(self.frontend, f"trendmicro_visionone_{kind}_timestamp", to)
                            since = to
                            to += timedelta(minutes=1)
                            self.frontend.save()
                            success = True
                        else:
                            logger.error(
                                f"[{__parser__}]:execute: Failed on {kind} logs, error status received",
                                extra={'frontend': str(self.frontend)})
                            retry -= 1

                    else:
                        logger.info(
                            f"[{__parser__}]:execute: Log collection for {kind}'s logs stopped at {getattr(self.frontend, f'trendmicro_visionone_{kind}_timestamp')}",
                            extra={'frontend': str(self.frontend)})

                except requests.exceptions.ReadTimeout as e:
                    logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
                    to -= (to - since) / 2
                    if (to - since) < timedelta(seconds=MIN_QUERY_INTERVAL):
                        logger.error(
                            f"[{__parser__}]:execute: Failed on {kind} logs, time range too small between {since} and {to}",
                            extra={'frontend': str(self.frontend)})
                        break
                    else:
                        logger.info(
                            f"[{__parser__}]:execute: Will retry with smaller time range..",
                            extra={'frontend': str(self.frontend)})

                except Exception as e:
                    logger.error(f"[{__parser__}]:execute: Failed on {kind} logs, between time of {since} and {to} : {e}", extra={'frontend': str(self.frontend)})
                    logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
                    retry -= 1

            if not success and retry <= 0:
                logger.error(f"[{__parser__}]:execute: Failed on {kind} logs, max of {max_retries} retries exceeded",
                             extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

    def test(self):
        since = timezone.now() - timedelta(hours=24)
        to = timezone.now()
        start_time = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        start_time_oat = (since + timedelta(hours=23, minutes=59)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = to.strftime("%Y-%m-%dT%H:%M:%SZ")
        auditlogs = list()
        detection_logs = list()

        try:
            alerts, status = self._get_alerts(start_time, end_time)
            if status:
                auditlogs, status = self._get_auditlogs(start_time, end_time)
            if status:
                detection_logs, status = self._get_OAT(start_time_oat, end_time)

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
