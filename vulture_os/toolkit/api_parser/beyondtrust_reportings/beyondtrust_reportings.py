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
__doc__ = 'Beyondtrust Reportings API'
__parser__ = 'Beyondtrust Reportings'

from json import dumps as json_dumps
import logging

import requests
from requests.exceptions import JSONDecodeError
from xmltodict import parse as xmltodict_parse

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class BeyondtrustReportingsAPIError(Exception):
    pass


class BeyondtrustReportingsParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    DURATION = 86400  # Fetch 24h of logs (in seconds)

    def __init__(self, data):
        super().__init__(data)

        self.beyondtrust_reportings_client_id = data["beyondtrust_reportings_client_id"]
        self.beyondtrust_reportings_secret = data["beyondtrust_reportings_secret"]
        self.beyondtrust_reportings_host = data["beyondtrust_reportings_host"]
        self.beyondtrust_reportings_api_token = data.get("beyondtrust_reportings_api_token", {})

        self.allowed_reporting_types = {
            "Team": data.get("beyondtrust_reportings_get_team_logs", False),
            "AccessSession": data.get("beyondtrust_reportings_get_access_session_logs", False),
            "VaultAccountActivity": data.get("beyondtrust_reportings_get_vault_account_activity_logs", False),
            "SupportSession": data.get("beyondtrust_reportings_get_support_session_logs", False),
        }

        self.beyondtrust_reportings_host = "https://" + self.beyondtrust_reportings_host.split("://")[-1].rstrip("/")

        self.session = None

    def save_access_token(self):
        try:
            if self.frontend:
                self.frontend.beyondtrust_reportings_api_token = self.beyondtrust_reportings_api_token
        except Exception as e:
            raise BeyondtrustReportingsAPIError(f"Unable to save access token: {e}")

    @property
    def api_token(self):
        if not self.beyondtrust_reportings_api_token or datetime.fromtimestamp(self.beyondtrust_reportings_api_token['timestamp'], tz=timezone.utc) < (timezone.now()  + timedelta(minutes=5)):
            token, expires_in = self.get_token()
            self.beyondtrust_reportings_api_token = dict(bearer=token, timestamp=(timezone.now() + timedelta(seconds=expires_in)).timestamp())
            self.save_access_token()
            msg = "Collector authenticated, new credentials saved"
            logger.info(f"[{__parser__}] api_token: {msg}", extra={'frontend': str(self.frontend)})
        return self.beyondtrust_reportings_api_token['bearer']

    def get_token(self):
        basic = requests.auth.HTTPBasicAuth(self.beyondtrust_reportings_client_id, self.beyondtrust_reportings_secret)
        res = requests.post(f'{self.beyondtrust_reportings_host}/oauth2/token',
                            data={"grant_type": "client_credentials"},
                            auth=basic,
                            proxies=self.proxies,
                            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)
        res.raise_for_status()
        try:
            res_json = res.json()
        except JSONDecodeError as err:
            raise BeyondtrustReportingsAPIError(f"Error on getting token: {err}")
        else:
            if any(k not in res_json.keys() for k in ('access_token', 'expires_in')):
                raise BeyondtrustReportingsAPIError("Error while getting a new access token: response does not contain access_token or expires_in keys")

            return res_json['access_token'], res_json['expires_in']

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                headers = self.HEADERS
                headers.update({'Authorization': f"Bearer {self.api_token}"})
                self.session.headers.update(headers)
        except Exception as err:
            raise BeyondtrustReportingsAPIError(f"Error on _connect(): {err}")

    def _execute_query(self, url, query={}, timeout=20, tries=1):
        while tries > 0 and not self.evt_stop.is_set():
            if self.session is None:
                self._connect()
            logger.info(f"[{__parser__}]:execute_query: URL: {url} , params: {query}", extra={'frontend': str(self.frontend)})
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
                tries -= 1
                if tries > 0:
                    self.evt_stop.wait(10.0)
                continue
            # Handle token expiration
            elif response.status_code == 401:
                logger.warning(f"[{__parser__}]:execute: 401 received, will try to re-authenticate...",
                            extra={'frontend': str(self.frontend)})
                self.session = None
                self.beyondtrust_reportings_api_token = None
                tries -= 1
                if tries > 0:
                    self.evt_stop.wait(5.0)
                continue
            elif response.status_code == 200:
                return response

        raise BeyondtrustReportingsAPIError("Maximum number of tries reached")

    def test(self):
        # Get the last 12 hours
        since = timezone.now() - timedelta(hours=12)
        err = ""
        for requested_type in self.allowed_reporting_types.keys():
            try:
                logs, _ = self.get_logs("reporting", requested_type, since)

                return {
                    "status": True,
                    "data": logs
                }
            except Exception as e:
                err = e
                continue

        logger.exception(f"{[__parser__]}:test: {str(err)}", extra={'frontend': str(self.frontend)})
        return {
            "status": False,
            "error": str(err)
        }

    def format_team_logs(self, logs):
        formated_logs = []
        try:
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
        except KeyError as e:
            logger.error(f"[{__parser__}] An error occurred while formating Team logs: {e}",
                        extra={'frontend': str(self.frontend)})

        return formated_logs

    def format_access_session_logs(self, logs):
        formated_logs = []
        try:
            sessions_logs = logs['session_list'].get('session', [])
            if not isinstance(sessions_logs, list):
                sessions_logs = [sessions_logs]

            for log in sessions_logs:
                del log['session_details']  # Avoid too long session log
                log["@timestamp"] = log["start_time"]["@timestamp"]
                formated_logs.append(log)
        except KeyError as e:
            logger.error(f"[{__parser__}] An error occurred while formating AccessSession logs: {e}",
                        extra={'frontend': str(self.frontend)})

        return formated_logs

    def format_vault_account_activity_list_logs(self, logs):
        try:
            formated_logs = logs['vault_account_activity_list'].get('vault_account_activity', [])
            if not isinstance(formated_logs, list):
                formated_logs = [formated_logs]
        except KeyError as e:
            logger.error(f"[{__parser__}] An error occurred while formating AccountActivityList logs: {e}",
                        extra={'frontend': str(self.frontend)})
        else:
            return formated_logs

    def format_support_session_logs(self, logs):
        try:
            formated_logs = logs.get('session_list', {}).get('session', [])

            if isinstance(formated_logs, dict):
                formated_logs = [formated_logs]

            for log in formated_logs:
                del log['session_details']  # Avoid too long session log
                log["@timestamp"] = log["start_time"]["@timestamp"]
        except KeyError as e:
            logger.error(f"[{__parser__}] An error occurred while formating AccountActivityList logs: {e}",
                        extra={'frontend': str(self.frontend)})
        else:
            return formated_logs

    def get_logs(self, resource: str, requested_type: str, since: datetime, tries: int = 1):
        url = f"{self.beyondtrust_reportings_host}/api/{resource}"

        parameters = {
            'start_time': int(since.timestamp()),
            'duration': self.DURATION,
            'generate_report': requested_type,
        }

        msg = f"Getting {self.DURATION} seconds of {requested_type} logs, starting from {since}"
        logger.info(f"[{__parser__}] get_logs: {msg}", extra={'frontend': str(self.frontend)})

        res = self._execute_query(url, query=parameters, tries=tries)
        logs = xmltodict_parse(res.text)

        if error := logs.get('error'):
            # if "report information matching your chosen criteria is available." in error.get('#text'):
            if any(x in error.get('#text') for x in ["correspondant à vos critères n’est disponible.", "matching your chosen criteria is available."]):
                return [], None
            msg = f"[{__parser__}]:get_logs: Error while getting '{requested_type}' logs : {error.get('#text')}"
            raise BeyondtrustReportingsAPIError(msg)

        # Return only list of events
        if resource == 'reporting' and requested_type == "Team":
            formated_logs = self.format_team_logs(logs)
        elif resource == 'reporting' and requested_type == "AccessSession":
            formated_logs = self.format_access_session_logs(logs)
        elif resource == 'reporting' and requested_type == "VaultAccountActivity":
            formated_logs = self.format_vault_account_activity_list_logs(logs)
        elif resource == 'reporting' and requested_type == "SupportSession":
            formated_logs = self.format_support_session_logs(logs)
        else:
            msg = f"[{__parser__}]:get_logs: Error while getting '{requested_type}' logs : This requested type is not allowed."
            raise BeyondtrustReportingsAPIError(msg)

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
        return json_dumps(cleaned_log)

    def execute(self):

        # Get reporting logs
        reporting_types = [r_type for r_type, value in self.allowed_reporting_types.items() if value]

        if not reporting_types:
            msg = f"[{__parser__}]:execute: Reporting types list cannot be empty."
            raise BeyondtrustReportingsAPIError(msg)

        for report_type in reporting_types:
            since = self.last_collected_timestamps.get(f"beyondtrust_reportings_{report_type}") or (timezone.now() - timedelta(days=30))

            msg = f"Parser starting to get {report_type} logs from {since}"
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            while not self.evt_stop.is_set():

                logs, last_datetime = self.get_logs("reporting", report_type, since, tries=2)
                if logs:
                    self.write_to_file([self.format_log(log, "reporting", report_type) for log in logs])
                    # Downloading may take some while, so refresh token in Redis
                    self.update_lock()

                try:
                    last_datetime = datetime.fromtimestamp(int(last_datetime), tz=timezone.utc) + timedelta(seconds=1)
                    self.last_collected_timestamps[f"beyondtrust_reportings_{report_type}"] = last_datetime
                except (TypeError, ValueError):
                    # except if no logs because "last_datetime" == None
                    # If no logs where retrieved during the last 24hours,
                    # move forward 1h to prevent stagnate ad vitam eternam
                    if since < timezone.now() - timedelta(hours=24):
                        msg = "No logs, advancing timestamp by 1 hour(s)"
                        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                        self.last_collected_timestamps[f"beyondtrust_reportings_{report_type}"] = since + timedelta(hours=1)
                finally:
                    msg = "New timestamp for {report_type} is {timestamp}".format(
                        report_type=report_type,
                        timestamp=self.last_collected_timestamps[f"beyondtrust_reportings_{report_type}"]
                    )
                    logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                    since = self.last_collected_timestamps[f"beyondtrust_reportings_{report_type}"]

                if not logs:
                    break

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
