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
__author__ = "Robin Langlois"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'MessageTrace O365 API Parser'
__parser__ = 'MESSAGETRACE O365'


from datetime import timedelta, datetime
import json
import logging
import requests

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser
import msal

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class MessageTraceO365APIError(Exception):
    pass


class MessageTraceO365Parser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.messagetrace_o365_client_id = data.get('messagetrace_o365_client_id')
        self.messagetrace_o365_tenant_id = data.get('messagetrace_o365_tenant_id')
        self.messagetrace_o365_client_secret = data.get('messagetrace_o365_client_secret')

        self.grant_type = "client_credentials"

        self.authority = f"https://login.microsoftonline.com/{self.messagetrace_o365_tenant_id}"
        self.scope = ["https://outlook.office365.com/.default"]

        self.url = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc/MessageTrace"

        self.token_cache = msal.SerializableTokenCache()
        if self.frontend and self.frontend.messagetrace_o365_serialized_token:
            logger.info(f"[{__parser__}]:__init__: Loading cached token", extra={'frontend': str(self.frontend)})
            self.token_cache.deserialize(self.frontend.messagetrace_o365_serialized_token)


    def __connect(self):
        logger.info(f"[{__parser__}]:connect: Fetching token", extra={'frontend': str(self.frontend)})
        try:
            app = msal.ConfidentialClientApplication(
                self.messagetrace_o365_client_id,
                authority=self.authority,
                client_credential=self.messagetrace_o365_client_secret,
                token_cache=self.token_cache
            )
            token_result = app.acquire_token_for_client(scopes=self.scope)
            if self.token_cache.has_state_changed and self.frontend:
                logger.info(f"[{__parser__}]:execute: Token was refreshed", extra={'frontend': str(self.frontend)})
                self.frontend.messagetrace_o365_serialized_token = self.token_cache.serialize()
                self.frontend.save(update_fields=["messagetrace_o365_serialized_token"])
        # handle network-related errors
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"[{__parser__}]:connect: Network error while trying to get a new token: {e}",
                         extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not retrieve token, network error")
        except Exception as e:
            logger.error(f"[{__parser__}]:connect: Error while trying to get a new token: {e}",
                         extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not retrieve token, unknown error")

        if "error" in token_result:
            raise MessageTraceO365APIError("Could not retrieve token : " + token_result.get("error_description", "unknown error"))
        if "access_token" not in token_result:
            raise MessageTraceO365APIError("Could not retrieve token : missing access_token key")

        self.access_token = token_result["access_token"]

        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }


    def __execute_query(self, params):
        logger.info(f"[{__parser__}]:__execute_query: Sending query with params {params}", extra={'frontend': str(self.frontend)})
        data = None
        response = None
        try:
            response = requests.get(self.url,
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)
            response.raise_for_status()
            data = response.json()
            return data
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"[{__parser__}]:__execute_query: Network Error while executing query: {e}",
                         extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not fetch logs, network error")
        except requests.HTTPError as e:
            logger.error(f"[{__parser__}]:__execute_query: HTTP Error while executing query: {e}",
                         extra={'frontend': str(self.frontend)})
            if response and response.content:
                logger.info(f"[{__parser__}]:__execute_query: Status: {response.status_code}, Content: {response.content}",
                            extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not fetch logs, HTTP error")
        except json.JSONDecodeError as e:
            logger.error(f"[{__parser__}]:__execute_query: error while decoding json result: {e}",
                         extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not fetch logs, JSON decoding error")
        except Exception as e:
            logger.error(f"[{__parser__}]:__execute_query: unknown error {e}", extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not fetch logs, unknown error")


    def _get_logs(self, since, to, limit=None):
        self.__connect()
        filter_str = f"StartDate eq datetime'{since}' and EndDate eq datetime'{to}'"

        # without limit, max 2000 results
        params = {
            "$filter": filter_str,
            "$top": limit
        }

        data = self.__execute_query(params)
        try:
            logs = data["value"]
        except KeyError:
            logger.error(f"[{__parser__}]:_get_logs: Missing key 'value' in logs, reply is {data}",
                         extra={'frontend': str(self.frontend)})
            raise MessageTraceO365APIError("Could not fetch logs, response malformed")

        # the API does not support sorting by date
        logs.sort(key=lambda log: log["Received"])

        return logs


    def test(self):
        try:
            since = timezone.now() - timedelta(minutes=5)
            to = timezone.now() - timedelta(minutes=1)
            data = self._get_logs(since, to, limit=10)
            return {
                'status': True,
                'data': data
            }
        except MessageTraceO365APIError as e:
            return {
                'status': False,
                'error': str(e)
            }


    def format_log(self, log):
        # StartDate and EndDate are just the "since" and "to" queried and do not convey any log-related information
        del log["StartDate"]
        del log["EndDate"]
        return json.dumps(log)


    def execute(self):
        since = self.last_api_call or (timezone.now() - timedelta(days=7))
        to = min(timezone.now(), since + timedelta(hours=24))

        try:
            logger.info(f"[{__parser__}]:execute: Querying logs from {since} to {to}",
                        extra={'frontend': str(self.frontend)})
            logs = self._get_logs(since, to)

            if len(logs) > 0:
                self.write_to_file([self.format_log(log) for log in logs])
                last_timestamp = timezone.make_aware(datetime.fromisoformat(logs[-1]["Received"]))
                # avoid duplicate logs
                last_timestamp = last_timestamp + timedelta(milliseconds=1)
                logger.info(f"[{__parser__}]:execute: Received data, update timestamp to {last_timestamp}", extra={'frontend': str(self.frontend)})

                self.frontend.last_api_call = last_timestamp
                self.frontend.save(update_fields=["last_api_call"])
            elif since < timezone.now() - timedelta(hours=24):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                logger.info(f"[{__parser__}]:execute: Update timestamp "
                            f"to {since + timedelta(hours=1)}",
                            extra={'frontend': str(self.frontend)})
                self.frontend.last_api_call = since + timedelta(hours=1)
                self.frontend.save(update_fields=["last_api_call"])

        except Exception as e:
            raise MessageTraceO365APIError(e)

