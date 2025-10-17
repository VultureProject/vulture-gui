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

import json
import logging
from django.conf import settings
from django.utils import timezone, dateparse

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

    SCAN_LOG_TYPES = ["SUS", "MAL", "SPM"]  # Suspicious, Malicious and Spam

    def __init__(self, data):
        super().__init__(data)

        self.perception_point_x_ray_host = "https://" + data["perception_point_x_ray_host"].split("://")[-1].rstrip()
        self.token = data['perception_point_x_ray_token']
        self.perception_point_x_ray_organization_id = data['perception_point_x_ray_organization_id']
        self.perception_point_x_ray_environment_id = data['perception_point_x_ray_environment_id']
        self.perception_point_x_ray_case_types = data['perception_point_x_ray_case_types']

        self.session = None


    def _execute_query(self, url, query=None, timeout=10):
        retry = 1
        while retry <= 3 and not self.evt_stop.is_set():
            if self.session is None:
                self._connect()
            msg = f"call {url} with query {query} (retry: {retry})"
            logger.debug(f"[{__parser__}]:__execute_query: {msg}", extra={'frontend': str(self.frontend)})
            try:
                response = self.session.get(
                    url,
                    params=query,
                    timeout=timeout,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                )
                response.raise_for_status()
                return response.json()
            except exceptions.Timeout:
                logger.warning(f"[{__parser__}]:__execute_query: TimeoutError: retry += 1 (waiting 10s)",
                             extra={'frontend': str(self.frontend)})
                retry += 1
                self.evt_stop.wait(10.0)
                continue
            except exceptions.HTTPError as err:
                if err.response is not None:
                    if err.response.status_code in (401, 403):
                        logger.error(f"[{__parser__}]:__execute_query: Received a 401/403,"
                                    " token is not (longer) valid!",
                            extra={'frontend': str(self.frontend)})
                        raise PerceptionPointXRayAPIError("Invalid token")
                    if err.response.status_code == 429:
                        logger.error(f"[{__parser__}]:__execute_query: Received a 429,"
                                    " stopping collector and waiting for next run",
                            extra={'frontend': str(self.frontend)})
                        raise PerceptionPointXRayAPIError("Rate limit reached")
                logger.error(f"[{__parser__}]:__execute_query: Unknown error at PerceptionPointXRay API Call URL:"
                             f" {url}: {err}", extra={'frontend': str(self.frontend)})
                retry += 1
                self.evt_stop.wait(10.0)
            except decoder.JSONDecodeError as err:
                logger.error(f"[{__parser__}]:__execute_query: Could not decode JSON from answer: {err}",
                            extra={'frontend': str(self.frontend)})
                raise PerceptionPointXRayAPIError("JSON decoding error")
        msg = f"Error at PerceptionPointXRay API Call URL: {url}: Unable to get a correct response"
        logger.error(f"[{__parser__}]:__execute_query: {msg}", extra={'frontend': str(self.frontend)})
        raise PerceptionPointXRayAPIError("No response")


    def _connect(self):
        if self.session is None:
            self.session = Session()
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Token {self.token}"})
        return True


    def test(self):
        try:
            if self.session is None:
                self._connect()

            since = timezone.now() - timedelta(hours=24)
            to = timezone.now()

            response, _, _, _ = self.get_scan_logs(since, to, self.SCAN_LOG_TYPES[0], None)

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

    def execute(self):

        self.execute_cases()
        self.execute_scans()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})


    # SCAN methods
    def get_scan_details(self, scan_id):
        # Get details for every scan
        url = f"{self.perception_point_x_ray_host}/api/v1/scans/list/{scan_id}/"
        return self._execute_query(url)

    def get_last_scans(self, since, to, log_type, next=None):
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

    def get_scan_logs(self, since, to, log_type, next=None):
        last_scans = {}
        while not self.evt_stop.is_set():
            # Get the ideal timerange of logs to avoid errors if API returns more of 1000 logs
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
    def format_scan_log(log):
        log['timestamp_epoch'] = log['timestamp']
        log["attachment_details"] = [
            {
                "url": log.get("attachment", ""),
                "count": log.get("attachments_count", 0),
                "names": log.get("names", ""),
                "payload_type": log.get("payload_type", ""),
                "file": {
                    "extension": log.get("sample_file_type", ""),
                    "size": log.get("sample", {}).get("file_size", "")
                }
            }
        ]
        # Remove unused and big fields
        unused_fields = ["timestamp", "search_descendants", "warning_texts", "scan_tree"]
        for field in unused_fields:
            if field in log:
                del log[field]
        if "sample" in log:
            if "similarity_content_vector" in log["sample"]:
                del log["sample"]["similarity_content_vector"]
            if "disclaimers" in log["sample"]:
                del log["sample"]["disclaimers"]
        return dumps(log)

    def execute_scans(self):
        # Get "SCAN" logs

        # Warning : the fetched logs are ordered in ASC (no option is available in API doc)
        for log_type in self.SCAN_LOG_TYPES:
            since = self.last_collected_timestamps.get(f"perception_point_x_ray_scan_{log_type}") or (
                        timezone.now() - timedelta(days=30))
            to = min(since + timedelta(days=1), timezone.now())

            msg = f"Parser starting from {since} to {to} for log_type {log_type}"
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            has_more_logs = True
            next_url = None
            while not self.evt_stop.is_set() and has_more_logs:

                logs, has_more_logs, next_url, to = self.get_scan_logs(since, to, log_type, next_url)

                self.write_to_file([self.format_scan_log(log) for log in logs])
                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                if logs:
                    if has_more_logs:
                        max_timestamp = max(int(log.get("timestamp_epoch") * 10000000) for log in logs)
                        last_timestamp = datetime.fromtimestamp(max_timestamp / 10000000, tz=timezone.utc)
                        self.last_collected_timestamps[
                            f"perception_point_x_ray_{log_type}"] = last_timestamp + timedelta(
                            milliseconds=1)  # Add +1 ms for inclusive timestamp
                    else:
                        self.last_collected_timestamps[f"perception_point_x_ray_scan_{log_type}"] = to + timedelta(
                            milliseconds=1)  # Add +1 ms for inclusive timestamp
                elif since < timezone.now() - timedelta(hours=24):
                    # If no logs where retrieved during the last 24hours,
                    # move forward 1h to prevent stagnate ad vitam eternam
                    self.last_collected_timestamps[f"perception_point_x_ray_scan_{log_type}"] = since + timedelta(hours=1)

    # CASES methods
    def get_last_cases(self, since, next=None):
        if next:
            url = next
            payload = {}
        else:
            url = f"{self.perception_point_x_ray_host}/api/v2/xdr/cases/details/"
            payload = {
                "environment_id": self.perception_point_x_ray_environment_id,
                "from_date": int(since.timestamp()),
                "case_types[]": self.perception_point_x_ray_case_types,
                "statuses[]": "OPEN",
                "organization_id": self.perception_point_x_ray_organization_id
            }

        return self._execute_query(url, payload)

    def get_case_logs(self, since, next=None):
        last_cases = self.get_last_cases(since, next)

        logs = []
        for log in last_cases.get('results', []):
            # Filter only see hours, not min/sec. So we have to compare with last_api_call to avoid duplicates
            if updated_ts := dateparse.parse_datetime(log.get("updated_timestamp_utc")):
                if updated_ts >= since:
                    log["updated_timestamp"] = int(updated_ts.timestamp() * 1000000)
                    logs.append(log)
            else:
                logger.error(f"[{__parser__}]:get_case_logs: Unable to parse {log.get('updated_timestamp_utc')} date, skipping...",
                                 extra={'frontend': str(self.frontend)})

        return logs, last_cases.get('next')

    @staticmethod
    def format_case_log(log):
        # Remove unused and big fields
        allowed_fields = ["updated_timestamp", "org_id", "case_id", "status", "validity", "humanly_touched",
                          "severity",
                          "case_type", "creation_timestamp_utc", "updated_timestamp_utc", "name", "metadata"]
        new_log = {k: log[k] for k in allowed_fields if k in log}
        return dumps(new_log)

    def execute_cases(self):
        # Get "ATO" (CASES) logs

        since = self.last_collected_timestamps.get("perception_point_x_ray_cases") or (
                    timezone.now() - timedelta(days=30))

        msg = f"Parser starting from {since} to now for CASE logs"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        has_more_logs = True
        next_url = None
        while not self.evt_stop.is_set() and has_more_logs:

            logs, next_url = self.get_case_logs(since, next_url)
            self.write_to_file([self.format_case_log(log) for log in logs])
            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            if logs:
                max_timestamp = max(log.get("updated_timestamp") for log in logs)
                last_timestamp = datetime.fromtimestamp(max_timestamp / 1000000, tz=timezone.utc)
                self.last_collected_timestamps["perception_point_x_ray_cases"] = last_timestamp + timedelta(
                    microseconds=1)  # Add +1 ms for inclusive timestamp

            elif since < timezone.now() - timedelta(hours=24):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                self.last_collected_timestamps["perception_point_x_ray_cases"] = since + timedelta(hours=1)

            if not next_url:
                has_more_logs = False