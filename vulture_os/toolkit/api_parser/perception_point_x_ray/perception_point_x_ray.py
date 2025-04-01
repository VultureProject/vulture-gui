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
__author__ = "nlancon"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'PERCEPTION POINT X RAY API Parser'
__parser__ = 'PERCEPTION_POINT_X_RAY'

import logging
from django.conf import settings
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser

from requests import Session, exceptions
from json import dumps, decoder

from datetime import datetime, timedelta

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class PerceptionPointXRayAPIError(Exception):
    pass


class PerceptionPointXRayParser(ApiParser):

    HEADERS = {
        "Accept": "application/json"
    }

    LOG_TYPES = ["SUS", "MAL", "SPM"]  # Malicious, spam and suspicious

    def __init__(self, data):
        super().__init__(data)

        self.perception_point_x_ray_host = "https://" + data["perception_point_x_ray_host"].split("://")[-1].rstrip()
        self.token = data['perception_point_x_ray_token']

        self.session = None

    def _execute_query(self, url, query=None, timeout=10):

        retry = 1
        while retry <= 3:  # 3 retries max
            if self.session is None:
                self._connect()

            try:
                response = self.session.get(
                    url,
                    params=query,
                    timeout=timeout,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                )
            except exceptions.Timeout:
                logger.warning(f"[{__parser__}]:__execute_query: TimeoutError: retry += 1 (waiting 10s)",
                             extra={'frontend': str(self.frontend)})
                retry += 1
                self.evt_stop.wait(10.0)
                continue
            except Exception as e:
                logger.error(f"[{__parser__}]:__execute_query: Exception: {e}", extra={'frontend': str(self.frontend)})
                raise PerceptionPointXRayAPIError(f"[{__parser__}]:__execute_query: Error at request. Exception: {e}")
            else:
                if response.status_code == 200:
                    try:
                        return response.json()
                    except decoder.JSONDecodeError as e:
                        raise PerceptionPointXRayAPIError(
                            f"[{__parser__}]:__execute_query: Error at JSON decoding. Exception JSONDecodeError: {e}") from e

                elif response.status_code == 429:
                    logger.error(
                        f"[{__parser__}]:__execute_query: Error at PerceptionPointXRay API Call URL: {url} Code: 429."
                        f"Wait a minute before continue. (retry {retry})",
                        extra={'frontend': str(self.frontend)})
                    retry += 1
                    self.evt_stop.wait(60.0)
                    continue

                else:
                    logger.error(f"[{__parser__}]:__execute_query: Error at PerceptionPointXRay API Call URL: {url} Code: {response.status_code} Content: {response.content}\n" \
                        f"Response : {response}", extra={'frontend': str(self.frontend)})
                    retry += 1
                    self.evt_stop.wait(10.0)
                    continue

        msg = f"Error at PerceptionPointXRay API Call URL: {url}: Unable to get a correct response"
        logger.error(f"[{__parser__}]:__execute_query: {msg}", extra={'frontend': str(self.frontend)})
        raise PerceptionPointXRayAPIError(msg)



    def _connect(self):
        if self.session is None:
            self.session = Session()
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Token {self.token}"})
            self.session.headers.update({"User-Agent": ""})
        return True

    def test(self):
        try:
            if self.session is None:
                self._connect()

            since = timezone.now() - timedelta(days=30)
            to = timezone.now()

            response, _, _, _ = self.get_logs(since, to, self.LOG_TYPES[0], None)

            return {
                "status": True,
                "data": response
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_scan_details(self, scan_id):
        # Get details for every scan
        url = f"{self.perception_point_x_ray_host}/api/v1/scans/list/{scan_id}/"
        return self._execute_query(url)

    def get_last_scans(self, since, to, log_type, next=None):
        if self.session is None:
            self._connect()

        if next:
            url = next
            payload = {}
        else:
            url = f"{self.perception_point_x_ray_host}/api/v1/scans/list/"
            payload = {
                "end": int(to.timestamp()),
                "start": int(since.timestamp()),
                "verbose_verdict": log_type,
            }

        return self._execute_query(url, payload)

    def get_logs(self, since, to, log_type, next=None):
        last_scans = {}
        while not self.evt_stop.is_set():  # Get the ideal timerange of logs to avoid errors if API returns more of 1000 logs
            last_scans = self.get_last_scans(since, to, log_type, next)
            if last_scans.get('count') >= 1000:
                to -= (to - since) / 2
                msg = f"API returns more than 1000 logs. Updating 'to' to {to} for log_type {log_type}"
                logger.warning(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
            else:
                break

        logs = []
        for scan in last_scans.get('results', []):
            scan_log = self.get_scan_details(scan["full_scan_id"])
            logs.append(scan_log)

        return logs, last_scans.get('has_more', False), last_scans.get('next'), to
    @staticmethod
    def format_log(log):
        log['timestamp_epoch'] = log['timestamp']
        # Remove unused and big fields
        unused_fields = ["timestamp", "search_descendants", "warning_texts", "scan_tree", "warning_texts", "similarity_content_vector", "disclaimers"]
        for field in unused_fields:
            try:
                del log[field]
            except KeyError:
                pass
        return dumps(log)

    def execute(self):
        # Warning : the fetched logs are ordered in ASC (no option is available in API doc)

        for log_type in self.LOG_TYPES:
            since = self.last_collected_timestamps.get(f"perception_point_x_ray_{log_type}") or (timezone.now() - timedelta(days=30))
            to = min(since + timedelta(days=1), timezone.now())

            msg = f"Parser starting from {since} to {to} for log_type {log_type}"
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            has_more_logs = True
            next_url = None
            while not self.evt_stop.is_set() and has_more_logs:

                logs, has_more_logs, next_url, to = self.get_logs(since, to, log_type, next_url)

                self.write_to_file([self.format_log(log) for log in logs])
                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                if logs and has_more_logs:
                    max_timestamp = max(int(log.get("timestamp_epoch") * 10000000) for log in logs)
                    last_timestamp = datetime.fromtimestamp(max_timestamp/10000000, tz=timezone.utc)
                    self.last_collected_timestamps[f"perception_point_x_ray_{log_type}"] = last_timestamp + timedelta(milliseconds=1)  # Add +1 ms for inclusive timestamp
                elif len(logs) == 0 and since < timezone.now() - timedelta(hours=24):
                    # If no logs where retrieved during the last 24hours,
                    # move forward 1h to prevent stagnate ad vitam eternam
                    self.last_collected_timestamps[f"perception_point_x_ray_{log_type}"] = since + timedelta(hours=1)
                else:
                    self.last_collected_timestamps[f"perception_point_x_ray_{log_type}"] = to + timedelta(milliseconds=1)  # Add +1 ms for inclusive timestamp

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
