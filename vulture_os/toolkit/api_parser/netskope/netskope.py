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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Netskope API Parser'
__parser__ = 'NETSKOPE'

import json
import logging
import requests

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class NetskopeAPIError(Exception):
    pass


class NetskopeParser(ApiParser):
    ENDPOINT = "/api/v2/events/data/"
    BULK_SIZE = 1000

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.netskope_host = data["netskope_host"]
        self.netskope_apikey = data["netskope_apikey"]
        self.netskope_get_page_logs = data["netskope_get_page_logs"]
        self.netskope_get_network_logs = data["netskope_get_network_logs"]
        self.netskope_get_application_logs = data["netskope_get_application_logs"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers.update({'Netskope-Api-Token': self.netskope_apikey})
                for k,v in self.HEADERS.items():
                    self.session.headers.update({k:v})

        except Exception as err:
            raise NetskopeAPIError(err)

    def test(self):
        try:
            logs = []
            logtypes = ["alert"]
            if self.netskope_get_page_logs:
                logtypes.append("page")
            if self.netskope_get_network_logs:
                logtypes.append("network")
            if self.netskope_get_application_logs:
                logtypes.append("application")
            for logtype in logtypes:
                logs.extend(self.get_logs(timezone.now()-timedelta(days=10), logtype=logtype).get("result"))

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since, to=timezone.now(), cursor=0, logtype="alert"):
        self._connect()

        url = f"https://{self.netskope_host}{self.ENDPOINT}{logtype}"

        # Format timestamp for query, API wants a Z at the end
        if isinstance(since, datetime):
            since = int(since.timestamp())
        if isinstance(to, datetime):
            to = int(to.timestamp())
        query = {
            'starttime': since,
            'endtime': to,
            'limit': self.BULK_SIZE,
            'offset': cursor
        }
        response = self.session.get(
            url,
            params=query,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )
        response.raise_for_status() # raises exception if != 2XX
        if response.status_code == 200:
            result = response.json()
        else:
            logger.exception(f"[{__parser__}]:get logs: API return status code: {response.status_code}, response: {response}", extra={'frontend': str(self.frontend)})
        assert result['ok'] == 1, result['message']
        return result

    def parse_alert_log(self, log):
        if log['timestamp'] > self.upper_timestamp:
            self.upper_timestamp = log['timestamp']
        log['alert_type'] = log['alert_type'].lower()
        return json.dumps(log)

    def execute(self):
        logtypes = ["alert"]
        if self.netskope_get_page_logs:
            logtypes.append("page")
        if self.netskope_get_network_logs:
            logtypes.append("network")
        if self.netskope_get_application_logs:
            logtypes.append("application")
        for logtype in logtypes:
            since = self.last_collected_timestamps.get(logtype, self.last_api_call) or (timezone.now() - timedelta(hours=24))
            self.upper_timestamp = since.timestamp()
            to = min(timezone.now(), since + timedelta(hours=24))
            offset = 0
            logs = []
            log_ids = set()

            while offset%self.BULK_SIZE == 0:

                response = self.get_logs(since, to, offset, logtype)

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                new_logs = response['result']
                if len(new_logs) == 0:
                    logger.info(f"[{__parser__}][execute]: No more log to fetch. End of the parsing",
                                extra={'frontend': str(self.frontend)})
                    break
                # Remove duplicated logs
                log_ids = log_ids.union(set([log.get("_event_id", "") for log in logs]))
                for new_log in new_logs:
                    if new_log.get("_event_id", "") not in log_ids:
                        logs.append(new_log)
                offset += len(new_logs)

            if logtype == "alert":
                self.write_to_file([self.parse_alert_log(log) for log in logs])
            else:
                self.write_to_file([json.dumps(log) for log in logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            if offset > 0:
                logger.info(f"[{__parser__}][execute]: Total logs fetched : {offset}",
                            extra={'frontend': str(self.frontend)})
                self.last_collected_timestamps[logtype] = to

            elif self.last_api_call < timezone.now() - timedelta(hours=24):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                self.last_collected_timestamps[logtype] = self.last_collected_timestamps[logtype] + timedelta(hours=1)

            logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
