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
__author__ = "tbertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Vadesecure O365 API Parser'
__parser__ = 'VADESECURE O365'

import json
import logging
import requests

from datetime import datetime
from django.conf import settings
from django.utils import dateparse, timezone
import time

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')



class VadesecureO365APIError(Exception):
    pass


class VadesecureO365Parser(ApiParser):
    TOKEN_ENDPOINT = "https://api.vadesecure.com/oauth2/v2/token"


    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json',
    }

    def __init__(self, data):
        """
            vadesecure_o365_host
            vadesecure_o365_tenant
            vadesecure_o365_client_id
            vadesecure_o365_client_secret
        """
        super().__init__(data)

        self.vadesecure_o365_host = data["vadesecure_o365_host"].rstrip("/")
        if not self.vadesecure_o365_host.startswith('https://'):
            self.vadesecure_o365_host = f"https://{self.vadesecure_o365_host}"

        self.vadesecure_o365_tenant = data["vadesecure_o365_tenant"]
        self.vadesecure_o365_client_id = data["vadesecure_o365_client_id"]
        self.vadesecure_o365_client_secret = data["vadesecure_o365_client_secret"]

        self.access_token = data.get("vadesecure_o365_access_token", None)
        self.expires_on = data.get("vadesecure_o365_access_token_expiry", None)


    def __connect(self, timeout=10):
        logger.info(f"[{__parser__}]:__connect: getting access token from {self.TOKEN_ENDPOINT}", extra={'frontend': str(self.frontend)})
        logger.debug(f"[{__parser__}]:__connect: url -> {self.TOKEN_ENDPOINT}, client_id -> {self.vadesecure_o365_client_id}, client_secret -> [masked], timeout -> {timeout}, proxies -> {self.proxies}", extra={'frontend': str(self.frontend)})

        response = requests.post(
            self.TOKEN_ENDPOINT,
            data={
                'grant_type': "client_credentials",
                'scope': "m365.api.read",
                'client_id': self.vadesecure_o365_client_id,
                'client_secret': self.vadesecure_o365_client_secret
            },
            timeout=timeout,
            proxies=self.proxies
        )

        if response.status_code != 200:
            if self.frontend:
                self.frontend.vadesecure_o365_access_token = None
                self.frontend.vadesecure_o365_access_token_expiry = None
                self.frontend.save()
            raise VadesecureO365APIError(f"Error on URL: {self.TOKEN_ENDPOINT} Status: {response.status_code} Reason/Content: {response.content}")

        data = response.json()

        self.access_token = data['access_token']
        # decrease value by 10 seconds to ensure token is refreshed before being invalid (while still using it for most of its validity time)
        self.expires_on = datetime.fromtimestamp(time.time() + int(data['expires_in']) - 10).replace(tzinfo=timezone.utc)

        if self.frontend:
            self.frontend.vadesecure_o365_access_token = self.access_token
            self.frontend.vadesecure_o365_access_token_expiry = self.expires_on
            self.frontend.save()

        logger.info(f"[{__parser__}]:__connect: Successfuly got a new token, valid until {self.expires_on}", extra={'frontend': str(self.frontend)})


    def _get_access_token(self):
        if not self.expires_on or not self.access_token or timezone.now() > self.expires_on:
            logger.debug(f"[{__parser__}]:_get_access_token: existing access token expired, need to get a new one", extra={'frontend': str(self.frontend)})
            self.__connect()
        else:
            logger.debug(f"[{__parser__}]:_get_access_token: existing access token valid until {self.expires_on}, no need to get a new one", extra={'frontend': str(self.frontend)})
            return self.access_token

        return self._get_access_token()


    def __execute_query(self, method, url, query, timeout=10):
        """
        send a query to the Vadesecure 0365 endpoint, using the access_token previously recovered
        """
        headers = self.HEADERS
        headers.update({"Authorization": f"Bearer {self._get_access_token()}"})

        logger.debug(f"[{__parser__}]:__execute_query: sending request to {url}", extra={'frontend': str(self.frontend)})

        if method == "POST":
            response = requests.post(
                url,
                json=query,
                headers=headers,
                timeout=timeout,
                proxies=self.proxies
            )
        else:
            raise VadesecureO365APIError(f"Error at Vadesecure request, unknown method : {method}")

        if response.status_code != 200:
            if self.frontend:
                self.frontend.vadesecure_o365_access_token = None
                self.frontend.vadesecure_o365_access_token_expiry = None
                self.frontend.save()
            logger.info(f"[{__parser__}]:__execute_query: Error while getting logs, invalidated cached access token for next try", extra={'frontend': str(self.frontend)})
            raise VadesecureO365APIError(f"Error at Vadesecure API Call URL: {url} Code: {response.status_code} Reason/Content: {response.content}")

        return response.json()


    def _get_emails_logs(self, start_from=None, limit=10):
        url = f"{self.vadesecure_o365_host}/api/v1/tenants/{self.vadesecure_o365_tenant}/logs/emails/search"
        query = {"sort": {"date": "asc"}, "limit": limit}

        if start_from:
            # Search_after pairs with the 'sort' parameter to return only elements corresponding to the sorted field after the element given
            # It's the equivalent of a 'from' (excluded) condition for the date
            # If search_after is not set, the API will return first instances of logs in database
            query.update({"search_after": start_from})

        logger.info(f"[{__parser__}]:_get_emails_logs: running query on host {self.vadesecure_o365_host}, with tenant {self.vadesecure_o365_tenant} and arguments {query}", extra={'frontend': str(self.frontend)})
        results = self.__execute_query("POST", url, query)

        try:
            return results["result"]["messages"]
        except KeyError:
            logger.error(f"[{__parser__}]:_get_emails_logs: Could not get results from logs", extra={'frontend': str(self.frontend)})
            logger.debug(f"[{__parser__}]:_get_emails_logs: got {results}", extra={'frontend': str(self.frontend)})
            raise VadesecureO365APIError(f"Error while fetching logs from {url}: could not get messages from result")


    def _format_log(self, log):
        if "date" in log:
            # parse datetime using django utils to strictly format the output (variable precision in sub-second field)
            parsed_date = dateparse.parse_datetime(log['date'])
            if parsed_date:
                log["date"] = parsed_date.isoformat().replace("+00:00", "Z")
        return log


    def execute(self):
        """
            Central function to fetch logs
        """
        start_from = self.last_api_call.isoformat().replace("+00:00", "Z")
        more_logs = 1

        while more_logs:
            data = []
            logs = self._get_emails_logs(start_from, limit=200)

            if logs:
                more_logs = 1
                logger.info(f"[{__parser__}]:execute: got {len(logs)} logs", extra={'frontend': str(self.frontend)})
                for log in logs:
                    data.append(json.dumps(self._format_log(log)))

                try:
                    start_from = logs[-1]['date']
                except KeyError:
                    logger.error(f"[{__parser__}]:execute: Could not get 'date' key from last log", extra={'frontend': str(self.frontend)})
                    logger.debug(f"[{__parser__}]:execute: log line is '{logs[-1]}'", extra={'frontend': str(self.frontend)})
                    raise VadesecureO365APIError(f"Could not get date from log")

                # Writting may take a while, so refresh token in Redis
                self.update_lock()
                self.write_to_file(data)
            else:
                logger.info(f"[{__parser__}]:execute: finished processing logs", extra={'frontend': str(self.frontend)})
                more_logs = 0

        self.frontend.last_api_call = dateparse.parse_datetime(start_from)
        self.frontend.save()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})


    def test(self):
        logger.info(f"[{__parser__}]:test: Launching test", extra={'frontend': str(self.frontend)})

        try:
            # Invalidate potential access_token to force a refresh with updated parameters
            self.expires_on = None
            result = self._get_emails_logs()

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
