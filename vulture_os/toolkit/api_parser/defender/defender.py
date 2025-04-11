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
__author__ = "Theo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Microsoft Defender o365 API Parser toolkit'
__parser__ = 'DEFENDER'


import time
import json
import logging

from oauthlib.oauth2 import BackendApplicationClient
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from requests_oauthlib import OAuth2Session

from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class DefenderAPIError(Exception):
    pass


class DefenderParser(ApiParser):
    # Defender resource to provide during token creation, this is for Microsoft API
    DEFENDER_RESOURCE = "https://graph.windows.net"
    # (EU) Defender API point to get logs once a token has been generated
    API_BASE_URL = "https://wdatp-alertexporter-eu.windows.com"

    def __init__(self, data):
        super().__init__(data)

        self.token_endpoint = data["defender_token_endpoint"]
        self.client_id = data["defender_client_id"]
        self.client_secret = data["defender_client_secret"]
        self.session_expire = time.time()

        # Initialize OAuthSession for Oauth2.0 Microsoft specification
        client = BackendApplicationClient(client_id=self.client_id)
        self.oauthSession = OAuth2Session(client=client)
        self.oauthSession.proxies = self.proxies


    def __str__(self):
        return f"""token_endpoint: {self.token_endpoint}, client_id: {self.client_id}, client_secret: {self.client_secret}, session_expire: {self.session_expire}"""

    def _connect(self):
        try:
            # Avoid the uncertain period when token is soon to be invalidated by taking a 10 seconds security
            if time.time() >= self.session_expire - 10:

                try:
                    self.oauthSession.fetch_token(token_url=self.token_endpoint, client_id=self.client_id,
                                    client_secret=self.client_secret, resource=self.DEFENDER_RESOURCE)
                    self.session_expire = self.oauthSession.token['expires_on']
                except KeyError:
                    logger.critical(f"{[__parser__]}:_connect: Missing 'expires_on' key in token", extra={'frontend': str(self.frontend)})
                    raise DefenderAPIError("DEFENDER API: Missing key in generated Oauth2 token")
                except OAuth2Error as e:
                    logger.error(f"{[__parser__]}:_connect: Error while trying to get a new OAuth token from Microsoft", extra={'frontend': str(self.frontend)})
                    logger.exception(str(e), extra={'frontend': str(self.frontend)})
                    logger.debug(f"{[__parser__]}:_connect: params -> {str(self)}", extra={'frontend': str(self.frontend)})
                    raise DefenderAPIError("DEFENDER API: Error while getting a new OAuth token")

            return True

        except Exception as e:
            raise DefenderAPIError(str(e))


    def get_logs(self, logs_from=None, logs_to=None, test=False):
        self._connect()

        url = f"{self.API_BASE_URL}/api/alerts"
        params = {}


        if test:
            # Get logs from last 2 months, but limit response to 5 alerts
            # There aren't generaly many logs, so lookup should be on a long time range
            params.update({'ago': 'P2M', 'limit': 5})
        else:
            if logs_to:
                params.update({'untilTimeUtc': logs_to.isoformat().replace('+00:00', "Z")})
            if logs_from:
                params.update({'sinceTimeUtc': logs_from.isoformat().replace('+00:00', "Z")})

        try:
            logger.info(f"[{__parser__}]:execute_query: URL: {url} , method: GET, params: {params}", extra={'frontend': str(self.frontend)})
            response = self.oauthSession.get(
                url,
                params=params,
            )
        except OAuth2Error as e:
            logger.error(f"{[__parser__]}:get_logs: Internal authentication error wile trying to get logs: '{str(e)}'", extra={'frontend': str(self.frontend)})
            logger.debug(f"{[__parser__]}:get_logs: API parameters: {str(self)}, request parameters: {params}", extra={'frontend': str(self.frontend)})
            raise DefenderAPIError(str(e))

        if response.status_code == 401:
            logger.error(f"{[__parser__]}:get_logs: Authentication failure while trying to get logs", extra={'frontend': str(self.frontend)})
            logger.debug(f"{[__parser__]}:get_logs: API parameters: {str(self)}, request parameters: {params}", extra={'frontend': str(self.frontend)})
            raise DefenderAPIError("Authentication failed (401): {response.body}")
        elif response.status_code == 403:
            logger.error(f"{[__parser__]}:get_logs: Authorization error, domain(s) might not be managed by the tenant administrator", extra={'frontend': str(self.frontend)})
            logger.debug(f"{[__parser__]}:get_logs: API parameters: {str(self)}, request parameters: {params}", extra={'frontend': str(self.frontend)})
            raise DefenderAPIError("Unauthorized, check Defender application parameters")
        elif response.status_code != 200:
            logger.error(f"{[__parser__]}:get_logs: Could not get Defender logs : status code is {response.status_code} with message '{response.text}'", extra={'frontend': str(self.frontend)})
            raise DefenderAPIError("Could not get Defender logs")

        content = response.json()
        logger.info(f"{[__parser__]}:get_logs: got {len(content)} new lines", extra={'frontend': str(self.frontend)})
        return content


    def test(self):
        try:
            logs = self.get_logs(test=True)

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


    def execute(self):
        # Get a batch of 24h at most to avoid running the parser for too long
        logs_from = self.last_api_call
        logs_to = min(timezone.now(), logs_from + timedelta(hours=24))
        logs = self.get_logs(logs_from=logs_from, logs_to=logs_to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        if len(logs) > 0:

            # All alerts are retrieved, reset timezone to now (+1ms to avoid repeating last log)
            self.frontend.last_api_call = logs_to + timedelta(milliseconds=1)
            self.frontend.save(update_fields=["last_api_call"])

            self.write_to_file([json.dumps(l) for l in logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        logger.info(f"{[__parser__]}:execute: Parsing done.", extra={'frontend': str(self.frontend)})