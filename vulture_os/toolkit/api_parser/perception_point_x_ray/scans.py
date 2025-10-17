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
from datetime import timedelta, datetime
from json import dumps
from django.conf import settings
from django.utils import dateparse, timezone


class ScanMixin:

    SCAN_LOG_TYPES = ["SUS", "MAL", "SPM"]  # Suspicious, Malicious and Spam

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
                self.logger.warning(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
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
            self.logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

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