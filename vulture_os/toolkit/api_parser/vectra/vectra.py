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
__credits__ = ["Kevin Guillemot"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'VECTRA API'
__parser__ = 'VECTRA'

import logging
import time

import requests
import json
from copy import deepcopy
from datetime import timedelta, datetime
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class VectraAPIError(Exception):
    pass


class VectraParser(ApiParser):

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }
    TOKEN_ENDPOINT = "oauth2/token"

    def __init__(self, data):
        super().__init__(data)

        self.vectra_host = data["vectra_host"]
        self.vectra_client_id = data["vectra_client_id"]
        self.vectra_secret_key = data["vectra_secret_key"]

        self.vectra_access_token = data.get("vectra_access_token")
        self.vectra_expire_at = data.get("vectra_expire_at")

        self.session = None

    def save_access_token(self):
        try:
            if self.frontend:
                self.frontend.vectra_access_token = self.vectra_access_token
                self.frontend.vectra_expire_at = self.vectra_expire_at
                self.frontend.save()
        except Exception as e:
            raise VectraAPIError(f"Unable to save access token: {e}")

    def get_auth_token(self):
        res = {}

        logger.info(f"[{__parser__}]:get_auth_token: Generating access token.", extra={'frontend': str(self.frontend)})
        url = self.vectra_host.rstrip("/") + '/' + self.TOKEN_ENDPOINT
        try:
            res = requests.post(
                url,
                auth=(self.vectra_client_id, self.vectra_secret_key),
                data={"grant_type": "client_credentials"},
                timeout=30,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            )

            if res.status_code == 429:
                raise VectraAPIError(f"Status-code {res.status_code} Exception: Too many requests.")
            elif res.status_code == 401:
                raise VectraAPIError(f"Status-code {res.status_code} Exception: Client ID or Client Secret is incorrect.")

            res.raise_for_status()

            logger.info(f"[{__parser__}]:get_auth_token: Access token generated.", extra={'frontend': str(self.frontend)})

            results = res.json()
            self.vectra_access_token = results.get("access_token")
            self.vectra_expire_at = timezone.now() + timedelta(seconds=results.get('expires_in'))
            self.save_access_token()
        except Exception as e:
            logger.error(f"[{__parser__}]:get_auth_token: An exception occurred: {e}", extra={'frontend': str(self.frontend)})
            if res:
                logger.error(f"[{__parser__}]:get_auth_token: response: {res.status_code}", extra={'frontend': str(self.frontend)})
            raise e

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                self.session.headers.update(headers)

            # Check for expiration with 10 seconds difference to be sure token will still be valid for some time
            if not self.vectra_access_token or not self.vectra_expire_at or (self.vectra_expire_at - timedelta(seconds=10)) < timezone.now():
                self.get_auth_token()

            self.session.headers.update({"Authorization": f"Bearer {self.vectra_access_token}"})
        except Exception as err:
            raise VectraAPIError(err)


    def get_data_from_entity_api(self, query = {}):
        results = list()
        # Ensure initial query object is not modified by the function
        internal_query = deepcopy(query)
        types = [
            "account",
            "host"
        ]
        for type_value in types:
            logger.info(f"[{__parser__}]:get_data_from_entity_api: Executing Entity {type_value} API task.", extra={'frontend': str(self.frontend)})
            internal_query.update({"type": type_value})
            response = self.__execute_query(internal_query, "api/v3.3/events/entity_scoring")

            results.extend(response.get("events", []))
            while "remaining_count" in response and "next_checkpoint" in response and response["remaining_count"] != 0:
                internal_query.update({"from": response["next_checkpoint"]})
                response = self.__execute_query(internal_query, "/api/v3.3/events/entity_scoring")
                results.extend(response.get("events", []))

        return results


    def get_logs(self, since: datetime, to: datetime):
        results = list()
        query = {"event_timestamp_gte": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "event_timestamp_lte": to.strftime("%Y-%m-%dT%H:%M:%SZ")}
        for endpoint in ["api/v3.3/events/detections"]:
            response = self.__execute_query(query, endpoint)
            results.extend(response.get("events", []))
        results.extend(self.get_data_from_entity_api(query))
        return results

    def __execute_query(self, query, endpoint, timeout=20):
        self._connect()

        url = self.vectra_host.strip('/') + '/' + endpoint.strip('/')

        msg = "URL : " + url + " Query : " + str(query)
        logger.info(f"[{__parser__}]:__execute_query: Request API : {msg}", extra={'frontend': str(self.frontend)})

        for _ in range(2):
            response = self.session.get(
                url,
                params=query,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            )

            if response.status_code == 200:
                return response.json()
            else:
                time.sleep(10)
                continue

        raise VectraAPIError(
            f"Error at Vectra API Call URL: {url} Code: {response.status_code} Content: {response.content}, Headers: {self.session.headers}, Query: {query}"
        )

    @staticmethod
    def format_log(log):
        return json.dumps(log)

    def test(self):
        logger.info(f"[{__parser__}]:test: Launching test", extra={'frontend': str(self.frontend)})

        try:
            since = timezone.now() - timedelta(hours=24)
            to = timezone.now()
            result = self.get_logs(since, to)

            return {
                "status": True,
                "data": result
            }
        except Exception as e:
            logger.error(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }


    def execute(self):
        try:
            ## GET LOGS ##
            since = self.frontend.last_api_call or (timezone.now() - timedelta(days=1))
            to = min(timezone.now(), since + timedelta(hours=24))

            logger.info(f"[{__parser__}]:execute: getting logs from {since} to {to}", extra={'frontend': str(self.frontend)})
            results = self.get_logs(since, to)
            self.update_lock()

            # Send those lines to Rsyslog
            self.write_to_file([self.format_log(l) for l in results])

            # And update lock after sending lines to Rsyslog
            self.update_lock()
            self.frontend.last_api_call = to
            self.frontend.save()
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})