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
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'HarfangLab EDR API Parser'
__parser__ = 'HARFANGLAB'


import json
import logging
import requests

from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class HarfangLabAPIError(Exception):
    pass


class HarfangLabParser(ApiParser):
    VERSION = "api/version/"
    ALERTS = "api/data/alert/alert/Alert/"
    THREATS = "api/data/alert/alert/Threat/"
    # STATUS = "api/status/"
    # CONFIG = "api/config/"
    # ALERT_DETAILS = "api/data/alert/alert/Alert/{id}/details/"
    # AGENT = "api/data/endpoint/Agent/"
    # AGENT_STATS = "api/data/endpoint/Agent/dashboard_stats/"
    # POLICY = "api/data/endpoint/Policy/"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.harfanglab_host = data["harfanglab_host"].rstrip("/")
        if not self.harfanglab_host.startswith('https://'):
            self.harfanglab_host = f"https://{self.harfanglab_host}"

        self.harfanglab_apikey = data["harfanglab_apikey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                headers.update({'Authorization': f"Token {self.harfanglab_apikey}"})

                self.session.headers.update(headers)

                response = self.session.get(
                    f'{self.harfanglab_host}/{self.VERSION}',
                    timeout=10,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                )
                assert response.status_code == 200, "Error connecting to HarfangLab API"

            return True

        except Exception as err:
            raise HarfangLabAPIError(err)

    def __execute_query(self, method, url, query, timeout=15):
        '''
        raw request doesn't handle the pagination natively
        '''
        self._connect()


        if method == "GET":
            logger.info(f"[{__parser__}]:execute_query: URL: {url} , method : GET , params: {query}", extra={'frontend': str(self.frontend)})
            response = self.session.get(url,
                params=query,
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        elif method == "POST":
            logger.info(f"[{__parser__}]:execute_query: URL: {url} , method : POST , data: {json.dumps(query)}", extra={'frontend': str(self.frontend)})
            response = self.session.post(url,
                data=json.dumps(query),
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        else:
            raise HarfangLabAPIError(f"Error at HarfangLab request, unknown method : {method}")

        # response.raise_for_status()
        if response.status_code != 200:
            raise HarfangLabAPIError(f"Error at HarfangLab API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):
        try:
            result = self.get_alerts(timezone.now()-timedelta(hours=12), timezone.now())

            return {
                "status": True,
                "data": result
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_alerts(self, since, to, index=0):
        alert_url = f"{self.harfanglab_host}/{self.ALERTS}"
        # Remove miliseconds - format not supported
        since_utc = since.isoformat().split('.')[0]
        to_utc = to.isoformat().split('.')[0]

        if '+' not in since_utc:
            since_utc += "+00:00"
        if '+' not in to_utc:
            to_utc += "+00:00"

        payload = {
            'offset': index,
            'limit': 1000, # Mandatory
            'alert_time__gte': since_utc,
            'alert_time__lt': to_utc,
            'ordering': 'alert_time',
            'status': 'new,investigating,probable_false_positive'
        }
        logger.info(f"[{__parser__}]:get_alerts: HarfangLab query parameters : {payload}",
                     extra={'frontend': str(self.frontend)})
        return self.__execute_query("GET", alert_url, payload)

    def get_threats(self, since, to, index=0):
        threat_url = f"{self.harfanglab_host}/{self.THREATS}"
        # Remove miliseconds - format not supported
        since_utc = since.isoformat().split('.')[0]
        to_utc = to.isoformat().split('.')[0]

        if '+' not in since_utc:
            since_utc += "+00:00"
        if '+' not in to_utc:
            to_utc += "+00:00"

        payload = {
            'offset': index,
            'limit': 1000,  # Mandatory
            'first_seen__gte': since_utc,
            'first_seen__lt': to_utc,
            'ordering': 'first_seen',
            'status': 'new,investigating,probable_false_positive'
        }
        logger.debug(f"[{__parser__}]:get_threats: HarfangLab query parameters : {payload}",
                     extra={'frontend': str(self.frontend)})
        return self.__execute_query("GET", threat_url, payload)

    def format_log(self, log, log_type):
        log['url'] = self.harfanglab_host
        log['evt_type'] = log_type

        log['is_truncated_powershell'] = False
        log['is_frombase64string'] = False
        log['is_truncated_rule_content'] = False
        log['is_truncated_process_sigma_rule_content'] = False

        details_powershell = log.get('details_powershell', None)
        if details_powershell and isinstance(details_powershell, dict):
            powershell_command = details_powershell.get('PowershellCommand', None)
            if powershell_command and isinstance(powershell_command, str):
                if len(powershell_command) >= 16384:
                    log['details_powershell']['PowershellCommand'] = powershell_command[:16384]
                    log['is_truncated_powershell'] = True
                if "FromBase64String" in powershell_command:
                    log['is_frombase64string'] = True

        if details_rule_content := log.get('rule_content', None):
            if len(details_rule_content) >= 16384:
                log['rule_content'] = details_rule_content[:16384]
                log['is_truncated_rule_content'] = True

        if details_process_sigma_rule_content := log.get('process', {}).get('sigma_rule_content', None):
            if len(details_process_sigma_rule_content) >= 16384:
                log['process']['sigma_rule_content'] = details_process_sigma_rule_content[:16384]
                log['is_truncated_process_sigma_rule_content'] = True

        return json.dumps(log)

    def execute(self):
        for log_type in ["alerts", "threats"]:
            try:
                since = self.last_collected_timestamps.get(log_type, self.last_api_call) or (timezone.now() - timedelta(days=7))
                # Don't get the last 10 minutes of logs, as some can appear delayed at the API
                to = min(timezone.now() - timedelta(minutes=10), since + timedelta(hours=24))

                index = 0
                total = 1
                logs = list()

                msg = f"{log_type}: parser starting from {since} to {to}."
                logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                while index < total:
                    get_func = getattr(self, f"get_{log_type}")
                    response = get_func(since, to, index)

                    # Downloading may take some while, so refresh token in Redis
                    self.update_lock()

                    logs += response['results']

                    total = int(response['count'])
                    msg = f"{log_type}: got {total} lines available"
                    logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                    if total == 0:
                        """
                        Means that there are no logs available. It may be for two
                        reasons: no log during this period or logs not available at
                        request time. If there are no logs, no need to write them.
                        """
                        break

                    if total >= 10000:
                        """
                        API have a return threshold set to 10k logs by default (maybe elastic underlying layer)
                        for every server response. This leads to an infinite loop in case of a large volume returned
                        on the requested time range (mostly ~0.001eps but spikes can be much larger)
                        """
                        msg = f"{log_type}: retrieved {total} lines >= 10k logs, shortening time range to avoid API error"
                        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                        to -= (to - since)/2
                        index = 0
                        logs = list()
                        continue

                    index += len(logs)
                    msg = f"{log_type}: retrieved {index} lines"
                    logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                self.write_to_file([self.format_log(l, log_type) for l in logs])
                # Writting may take some while, so refresh token in Redis
                self.update_lock()

                self.last_collected_timestamps[log_type] = to
                logger.info(f"[{__parser__}]:execute: last_collected timestamp of type {log_type} is updated to {to}", extra={'frontend': str(self.frontend)})

            except Exception as e:
                logger.error(f"[{__parser__}]:execute: Parsing error for type \"{log_type}\": {e}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
