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
__author__ = "Nicolas Lançon"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Beyondtrust PRA API'
__parser__ = 'Beyondtrust PRA'

# WARNING : THIS COLLECTOR IS DEPRECATED. PLEASE DO NOT UPDATE IT AND USE BEYONDTRUST_REPORTINGS INSTEAD

import json
import logging
from copy import deepcopy

import requests
import xmltodict

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class BeyondtrustPRAAPIError(Exception):
    pass


class BeyondtrustPRAParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    DURATION = 86400  # Fetch 24h of logs (in seconds)

    def __init__(self, data):
        super().__init__(data)

        self.beyondtrust_pra_client_id = data["beyondtrust_pra_client_id"]
        self.beyondtrust_pra_secret = data["beyondtrust_pra_secret"]
        self.beyondtrust_pra_host = data["beyondtrust_pra_host"]
        self.beyondtrust_pra_api_token = data.get("beyondtrust_pra_api_token", {})

        if not self.beyondtrust_pra_host.startswith('https://') and not self.beyondtrust_pra_host.startswith('http://'):
            self.beyondtrust_pra_host = f"https://{self.beyondtrust_pra_host}"
        self.beyondtrust_pra_host = self.beyondtrust_pra_host.rstrip("/")

        self.session = None

    def save_access_token(self):
        try:
            if self.frontend:
                self.frontend.beyondtrust_pra_api_token = self.beyondtrust_pra_api_token
                self.frontend.save(update_fields=['beyondtrust_pra_api_token'])
        except Exception as e:
            raise BeyondtrustPRAAPIError(f"Unable to save access token: {e}")

    @property
    def api_token(self):
        if not self.beyondtrust_pra_api_token or datetime.fromtimestamp(self.beyondtrust_pra_api_token['timestamp'], tz=timezone.utc) < (timezone.now()  + timedelta(minutes=5)):
            token, expires_in = self.get_token()
            self.beyondtrust_pra_api_token = dict(bearer=token, timestamp=(timezone.now() + timedelta(seconds=expires_in)).timestamp())
            self.save_access_token()
            msg = "Collector authenticated, new credentials saved"
            logger.info(f"[{__parser__}] api_token: {msg}", extra={'frontend': str(self.frontend)})
        return self.beyondtrust_pra_api_token['bearer']

    def get_token(self):
        basic = requests.auth.HTTPBasicAuth(self.beyondtrust_pra_client_id, self.beyondtrust_pra_secret)
        res = requests.post(f'{self.beyondtrust_pra_host}/oauth2/token',
                            data={"grant_type": "client_credentials"},
                            auth=basic,
                            proxies=self.proxies,
                            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)
        res.raise_for_status()
        res_json = res.json()
        return res_json['access_token'], res_json['expires_in']

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                headers = self.HEADERS
                headers.update({'Authorization': f"Bearer {self.api_token}"})
                self.session.headers.update(headers)
        except Exception as err:
            raise BeyondtrustPRAAPIError(err)

    def _execute_query(self, url, query=None, timeout=20):
        retry = 0
        while retry < 2 and not self.evt_stop.is_set():
            if self.session is None:
                self._connect()
            logger.info(f"[{__parser__}]:execute_query: URL: {url}, params: {query}, (try {retry+1})", extra={'frontend': str(self.frontend)})
            response = self.session.get(
                url,
                params=query,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            )
            # Handle rate-limiting
            if response.status_code == 429:
                logger.warning(f"[{__parser__}]:execute: API Rate limit exceeded, waiting 10 seconds...",
                            extra={'frontend': str(self.frontend)})
                self.evt_stop.wait(10.0)
                retry += 1
                continue
            # Handle token expiration
            if response.status_code == 401:
                logger.warning(f"[{__parser__}]:execute: 401 received, will try to re-authenticate...",
                            extra={'frontend': str(self.frontend)})
                self.session = None
                self.beyondtrust_pra_api_token = None
                self.evt_stop.wait(5.0)
                retry += 1
            elif response.status_code != 200:
                raise BeyondtrustPRAAPIError(
                    f"Error at Beyondtrust PRA API Call URL: {url} Code: {response.status_code} Content: {response.content}")
            else:
                return response

        raise BeyondtrustPRAAPIError(
            f"Error at Beyondtrust PRA API Call URL: {url} Code: {response.status_code} Content: {response.content}")

    def test(self):
        # Get the last 12 hours
        since = timezone.now() - timedelta(hours=12)
        try:
            logs, _ = self.get_logs("reporting", "Team", since)

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"{[__parser__]}:test: {str(e)}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    @staticmethod
    def format_team_logs(logs):
        formated_logs = []
        logs = logs['team_activity_list'].get('team_activity', [])
        if not isinstance(logs, list):
            logs = [logs]

        for log in logs:
            events = log['events']['event']
            if not isinstance(events, list):
                events = [events]

            for event in events:
                event['team'] = {
                    "name": log['@name'],
                    "id": log['@id'],
                }
                formated_logs.append(event)

        return formated_logs

    def format_event_value(self, event):
        child_session_details = deepcopy(event)

        if 'data' in event:
            data = {}
            event_value = event['data']['value']
            logger.debug(event_value, extra={'frontend': str(self.frontend)})

            if isinstance(event_value, list):
                for elem in event_value:
                    data[elem['@name']] = elem['@value']
            elif isinstance(event_value, dict):
                data[event_value['@name']] = event_value['@value']
            child_session_details['data'] = data

        return child_session_details

    def format_access_session_logs(self, logs):
        formated_logs = []
        sessions_logs = logs['session_list'].get('session', [])
        if not isinstance(sessions_logs, list):
            sessions_logs = [sessions_logs]

        for log in sessions_logs:
            log["@timestamp"] = log["start_time"]["@timestamp"]

            if not log.get('session_details', {}).get('event'):
                formated_logs.append(log)
                continue

            for event in log['session_details']['event']:
                child_log = deepcopy(log)
                child_log['session_details'] = self.format_event_value(event)
                formated_logs.append(child_log)

        return formated_logs

    @staticmethod
    def format_vault_account_activity_list_logs(logs):
        formated_logs = logs['vault_account_activity_list'].get('vault_account_activity', [])
        if not isinstance(formated_logs, list):
            formated_logs = [formated_logs]
        return formated_logs

    def get_logs(self, resource: str, requested_type: str, since: datetime):
        url = f"{self.beyondtrust_pra_host}/api/{resource}"

        parameters = {
            'start_time': int(since.timestamp()),
            'duration': self.DURATION,
            'generate_report': requested_type,
        }

        msg = f"Getting {self.DURATION} seconds of {requested_type} logs, starting from {since}"
        logger.info(f"[{__parser__}] get_logs: {msg}", extra={'frontend': str(self.frontend)})

        res = self._execute_query(url, query=parameters)

        try:
            logs = xmltodict.parse(res.text)
        except Exception:
            logger.warning(f"[{__parser__}]:get_logs: Unable to parse {res.text}", extra={'frontend': str(self.frontend)})
            return [], None

        if error := logs.get('error'):
            if "report information matching your chosen criteria is available." in error.get('#text'):
                return [], None
            msg = f"[{__parser__}]:get_logs: Error while getting '{requested_type}' logs : {error.get('#text')}"
            raise BeyondtrustPRAAPIError(msg)

        # Return only list of events
        if resource == 'reporting' and requested_type == "Team":
            formated_logs = self.format_team_logs(logs)
        elif resource == 'reporting' and requested_type == "AccessSession":
            formated_logs = self.format_access_session_logs(logs)
        elif resource == 'reporting' and requested_type == "VaultAccountActivity":
            formated_logs = self.format_vault_account_activity_list_logs(logs)
        else:
            msg = f"[{__parser__}]:get_logs: Error while getting '{requested_type}' logs : This requested type is not allowed."
            raise BeyondtrustPRAAPIError(msg)

        # ISO8601 timestamps are sortable as strings
        last_datetime = max((x['@timestamp'] for x in formated_logs), default=None)

        return formated_logs, last_datetime

    def remove_hash_from_keys(self, d):
        if isinstance(d, dict):
            return {key.replace('#', ''): self.remove_hash_from_keys(value) for key, value in d.items()}
        elif isinstance(d, list):
            return [self.remove_hash_from_keys(item) for item in d]
        else:
            return d

    def format_log(self, log, resource, requested_type):
        log["resource"] = resource
        log["requested_type"] = requested_type
        cleaned_log = self.remove_hash_from_keys(log)
        return json.dumps(cleaned_log)

    def execute(self):

        # Get reporting logs
        reporting_types = ["Team", "AccessSession", "VaultAccountActivity"]

        for report_type in reporting_types:
            since = self.last_collected_timestamps.get(f"beyondtrust_pra_{report_type}") or (timezone.now() - timedelta(days=30))

            msg = f"Parser starting to get {report_type} logs from {since}"
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            while since < timezone.now() - timedelta(hours=1) and not self.evt_stop.is_set():

                logs, last_datetime = self.get_logs("reporting", report_type, since)

                if logs:
                    self.write_to_file([self.format_log(log, "reporting", report_type) for log in logs])
                    # Downloading may take some while, so refresh token in Redis
                    self.update_lock()

                try:
                    last_datetime = datetime.fromtimestamp(int(last_datetime), tz=timezone.utc) + timedelta(seconds=1)
                    self.last_collected_timestamps[f"beyondtrust_pra_{report_type}"] = last_datetime
                except (TypeError, ValueError):
                    # Update timestamp +24 if since < now, otherwise +1
                    delta = 24 if since < timezone.now() - timedelta(hours=24) else 1
                    msg = f"No logs, advancing timestamp by {delta} hour(s)"
                    logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                    self.last_collected_timestamps[f"beyondtrust_pra_{report_type}"] = since + timedelta(hours=delta)
                finally:
                    msg = "Current timestamp for {report_type} is {timestamp}".format(
                        report_type=report_type,
                        timestamp=self.last_collected_timestamps[f"beyondtrust_pra_{report_type}"]
                    )
                    logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                    since = self.last_collected_timestamps[f"beyondtrust_pra_{report_type}"]

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
