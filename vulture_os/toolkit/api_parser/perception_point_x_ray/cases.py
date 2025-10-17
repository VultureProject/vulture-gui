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

class CaseMixin:
    def get_last_cases(self, since, next=None):
        if next:
            url = next
            payload = {}
        else:
            url = f"{self.perception_point_x_ray_host}/api/v2/xdr/cases/details/"
            payload = {
                "environment_id": 1,
                "from_date": int(since.timestamp()),
                "case_types[]": "354",
                "statuses[]": "OPEN",
                "organization_id": self.perception_point_x_ray_organization_id
            }

        return self._execute_query(url, payload)

    def get_case_logs(self, since, next=None):
        last_cases = self.get_last_cases(since, next)
        self.logger.info(f"[{__parser__}]:get_case_logs:")
        self.logger.info(dumps(last_cases))

        logs = []
        for log in last_cases.get('results', []):
            # Filter only see hours, not min/sec. So we have to compare with last_api_call to avoid duplicates
            updated_ts = dateparse.parse_datetime(log["updated_timestamp_utc"])
            if updated_ts >= since:
                log["updated_timestamp"] = int(updated_ts.timestamp() * 1000000)
                logs.append(log)
            else:
                self.logger.info(f"[{__parser__}]:get_case_logs: {updated_ts} < {since}, skipping...", extra={'frontend': str(self.frontend)})

        return logs, last_cases.get('next')

    @staticmethod
    def format_case_log(log):
        # Remove unused and big fields
        allowed_fields = ["updated_timestamp", "org_id", "case_id", "status", "validity", "humanly_touched", "severity",
                          "case_type", "creation_timestamp_utc", "updated_timestamp_utc", "name", "metadata"]
        new_log = {k: log[k] for k in allowed_fields if k in log}
        return dumps(new_log)

    def execute_cases(self):
        # Get "ATO" (CASES) logs

        since = self.last_collected_timestamps.get("perception_point_x_ray_cases") or (timezone.now() - timedelta(days=30))

        msg = f"Parser starting from {since} to now for CASE logs"
        self.logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

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