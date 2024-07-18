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
__author__ = "Gaultier Parain"
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'GATEWATCHER ALERTS API'
__parser__ = 'GATEWATCHER ALERTS'

import json
import logging
import requests

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class GatewatcherAlertsAPIError(Exception):
    pass

class GatewatcherAlertsParser(ApiParser):
    ALERTS_ENDPOINT = "/api/alerts/"
    RAW_ALERTS_ENDPOINT = "/api/raw-alerts/"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.gatewatcher_alerts_host = data["gatewatcher_alerts_host"]
        self.gatewatcher_alerts_api_key = data["gatewatcher_alerts_api_key"]
        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                self.session.headers.update(self.HEADERS)
                self.session.headers.update({'API-KEY': self.gatewatcher_alerts_api_key})
            return True

        except Exception as err:
            raise GatewatcherAlertsAPIError(err)

    def execute_query(self, url, params={}, timeout=20):

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies,
            timeout=timeout,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != 200:
            error = f"Error at Gatewatcher API Call: status : {response.status_code}, content : {response.content}"
            logger.error(f"[{__parser__}]:execute_query: {error}", extra={'frontend': str(self.frontend)})
            raise GatewatcherAlertsAPIError(error)

        return response.json()

    def get_logs(self, since, to):
        self._connect()
        alert_url = f"https://{self.gatewatcher_alerts_host}{self.ALERTS_ENDPOINT}"
        if isinstance(since, datetime):
            since = since.isoformat()
        if isinstance(to, datetime):
            to = to.isoformat()
        query = {
            'date_from': since,
            'date_to': to,
            'sort_by': "date",
            'page_size': 1000
        }
        results = []
        nb_logs = 0
        count = 1
        page = 1
        while(nb_logs < count):
            query['page'] = page
            logger.debug(f"{[__parser__]}:get_logs: params for request are '{query}'", extra={'frontend': str(self.frontend)})
            page += 1
            alerts = self.execute_query(alert_url, params=query)
            count = int(alerts["count"])
            nb_logs += len(alerts["results"])

            for alert in alerts.get("results", []):
                raw_alert_url = f"https://{self.gatewatcher_alerts_host}{self.RAW_ALERTS_ENDPOINT}/{alert['uuid']}"
                raw_alert = self.execute_query(raw_alert_url)
                results.append({'alert': alert, 'raw_alert': raw_alert})
                self.update_lock()

        return results

    def test(self):
        try:
            logs = self.get_logs(timezone.now() - timedelta(hours=2), timezone.now())
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

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        since = self.frontend.last_api_call or (timezone.now() - timedelta(hours=24))
        to = min(timezone.now(), since + timedelta(hours=24))

        logs = self.get_logs(since, to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        self.write_to_file([self.format_log(l) for l in logs])

        # Writting may take some while, so refresh token in Redis
        self.update_lock()
        # increment by 1ms to avoid duplication of logs
        if logs:
            self.frontend.last_api_call = datetime.fromisoformat(logs[-1]["alert"]["date"].replace("Z", "+00:00")) + timedelta(milliseconds=1)
            self.frontend.save()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})