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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Office365 API Parser'
__parser__ = 'OFFICE365'


import datetime
import json
import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class Office365ParseError(Exception):
    pass


class Office365APIError(Exception):
    pass


class Office365Parser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.office365_client_id = data.get('office365_client_id')
        self.office365_tenant_id = data.get('office365_tenant_id')
        self.office365_client_secret = data.get('office365_client_secret')

        self.grant_type = "client_credentials"

        self.office365_login_uri = "https://login.windows.net"

        version = "v1.0"

        self.office365_manage_uri = f"https://manage.office.com/api/{version}"

        self.access_token = False
        self.expires_on = False

    def _get_access_token(self):
        if not self.expires_on or datetime.datetime.now() > self.expires_on:
            self.__connect()
        else:
            return self.access_token

        return self._get_access_token()

    def __connect(self):
        url = f"{self.office365_login_uri}/{self.office365_tenant_id}/oauth2/token"

        logger.info(f"[{__parser__}]:connect: Requesting a new token", extra={'frontend': str(self.frontend)})
        response = requests.post(
            url,
            data={
                'grant_type': self.grant_type,
                'resource': 'https://manage.office.com',
                'client_id': self.office365_client_id,
                'client_assertion_type': 'urn%3Aietf%3Aparams%3Aoauth',
                'client_secret': self.office365_client_secret
            },
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )

        if response.status_code != 200:
            raise Office365APIError(f"Error on URL: {url} Status: {response.status_code} Content: {response.content}")

        data = response.json()

        self.access_token = data['access_token']
        self.expires_on = datetime.datetime.fromtimestamp(int(data['expires_on']))

    def _get_feed(self, test=False):
        access_token = self._get_access_token()

        url = f"{self.office365_manage_uri}/{self.office365_tenant_id}/activity/feed/subscriptions/content"

        response = requests.get(
            url,
            params={
                'contentType': "Audit.SharePoint",
                'PublisherIdentifier': self.office365_tenant_id
            },
            headers={
                "Authorization": f"Bearer {access_token}"
            },
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )

        for feed in response.json():
            print(feed['contentUri'])
            yield feed['contentUri']

            if test:
                break

    def _get_logs(self, url):
        access_token = self._get_access_token()

        response = requests.get(
            url,
            headers={
                'Authorization': f'Bearer {access_token}'
            },
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )

        if response.status_code != 200:
            raise Office365APIError(f"Error on URL: {url} Status: {response.status_code} Content: {response.content}")

        for tmp_log in response.json():
            yield tmp_log

    def parse_log(self, log):
        return log
        timestamp = datetime.datetime.strptime(log['CreationTime'], "%Y-%m-%dT%H:%M:%S")

        try:
            tmp = {
                "@timestamp": timestamp,
                "net_src_ip": log.get('ClientIP', '-'),
                "username": log.get("UserId", '-'),
                'http_user_agent': log.get('UserAgent', '-'),
            }
        except KeyError:
            raise

        return tmp

    def test(self):
        try:
            return self.execute(test=True)
        except Office365APIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self, test=False):
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
