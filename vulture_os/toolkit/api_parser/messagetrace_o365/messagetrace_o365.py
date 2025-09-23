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


import datetime
import json
import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
import msal

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class Office365ParseError(Exception):
    pass


class Office365APIError(Exception):
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

    def _get_access_token(self):
        # TODO : expires_on ?
        self.__connect()

        return self.access_token

    def __connect(self):
        logger.info(f"[{__parser__}]:connect: Requesting a new token", extra={'frontend': str(self.frontend)})
        app = msal.ConfidentialClientApplication(
            self.messagetrace_o365_client_id, authority=self.authority, client_credential=self.messagetrace_o365_client_secret
        )
        token_result = app.acquire_token_for_client(scopes=self.scope)
        self.access_token = token_result.get("access_token")
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }

        # TODO : check response
        # TODO : expires on ?


    def _get_logs(self, since, to):
        access_token = self._get_access_token()
        filter_str = f"StartDate eq datetime'{since}' and EndDate eq datetime'{to}'"

        # Paramètres de la requête
        params = {
            "$filter": filter_str,
            "$top": 100
        }

        # TODO : proxy
        response = requests.get(self.url,
                                headers=self.headers,
                                params=params,
                                proxies=self.proxies,
                                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)
        data = response

        if response.status_code != 200:
            # TODO : change exception
            raise Office365APIError(f"Error on URL: {self.url} Status: {response.status_code} Content: {response.content}")

        return data

    def test(self):
        try:
            end_date = datetime.datetime(2025, 9, 22, 14, 16, 2)
            start_date = datetime.datetime(2025, 9, 15, 14, 16, 1)

            to = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            since = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
            data = self._get_logs(since, to)
            return {
                'status': True,
                'data': data
            }
        except Office365APIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self, test=False):
        # TODO
        try:
            for feed_url in self._get_feed(test=test):
                data = []
                for log in self._get_logs(feed_url):
                    data.append(json.dumps(self.parse_log(log)))

                    if test:
                        return {
                            'status': True,
                            'data': data
                        }

                self.write_to_file(data)

            self.frontend.last_api_call = self.last_api_call
            self.frontend.save(update_fields=["last_api_call"])

        except Exception as e:
            raise Office365ParseError(e)
