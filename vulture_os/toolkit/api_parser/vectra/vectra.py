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
    KINDS = ["detections"]
    ENTITY_TYPES = ["account", "host"]

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
                self.frontend.save(update_fields=['vectra_access_token', 'vectra_expire_at'])
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


    def get_data_from_entity_api(self, since: datetime, to: datetime, entity_type: str):
        results = list()
        query = {"event_timestamp_gte": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "event_timestamp_lte": to.strftime("%Y-%m-%dT%H:%M:%SZ")}
        logger.info(f"[{__parser__}]:get_data_from_entity_api: Executing Entity {entity_type} API task.", extra={'frontend': str(self.frontend)})
        query.update({"type": entity_type})
        response = self.__execute_query(query, "api/v3.3/events/entity_scoring")
        results.extend(response.get("events", []))
        while "remaining_count" in response and "next_checkpoint" in response and response["remaining_count"] != 0:
            query.update({"from": response["next_checkpoint"]})
            response = self.__execute_query(query, "/api/v3.3/events/entity_scoring")
            results.extend(response.get("events", []))

        return results


    def get_logs(self, since: datetime, to: datetime, kind: str):
        query = {"event_timestamp_gte": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "event_timestamp_lte": to.strftime("%Y-%m-%dT%H:%M:%SZ")}
        endpoint = f"api/v3.3/events/{kind}"
        response = self.__execute_query(query, endpoint)
        return response.get("events", [])

    def __execute_query(self, query, endpoint, timeout=20):
        self._connect()

        url = self.vectra_host.strip('/') + '/' + endpoint.strip('/')

        msg = "URL : " + url + " Query : " + str(query)
        logger.info(f"[{__parser__}]:__execute_query: Request API : {msg}", extra={'frontend': str(self.frontend)})

        for _ in range(2):
            logger.info(f"[{__parser__}]:__execute_query: URL: {url} , params: {query}", extra={'frontend': str(self.frontend)})
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
            result = self.get_logs(since, to, "detections")

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
        ## GET LOGS ##
        kinds = self.KINDS
        results = list()
        logs = list()
        for kind in kinds:
            try:
                since = self.last_collected_timestamps.get(f"vectra_{kind}") or self.frontend.last_api_call or (timezone.now() - timedelta(days=1))
                to = min(timezone.now(), since + timedelta(hours=24))
                logger.info(f"[{__parser__}]:execute: getting logs from {since} to {to}", extra={'frontend': str(self.frontend)})
                results = self.get_logs(since, to, kind)
                if results:
                    new_timestamp = datetime.fromisoformat(results[-1]["event_timestamp"].replace("Z", "+00:00")) + timedelta(seconds=1)
                    logger.info(f"[{__parser__}][execute] :: Successfully got {len(results)} '{kind}' logs, updating last_collected_timestamps['vectra_{kind}'] -> {new_timestamp}", extra={'frontend': str(self.frontend)})
                    self.last_collected_timestamps[f"vectra_{kind}"] = new_timestamp
                    logs.extend(results)
                else:
                    if to == since + timedelta(hours=24):
                        self.last_collected_timestamps[f"vectra_{kind}"] = self.last_collected_timestamps[f"vectra_{kind}"] +timedelta(hours=1)
            except Exception as e:
                logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})

        ## GET DATA FROM ENTITIES ##
        entity_types = self.ENTITY_TYPES
        for entity_type in entity_types:
            since = self.last_collected_timestamps.get(f"vectra_{entity_type}") or self.frontend.last_api_call or (timezone.now() - timedelta(days=1))
            try:
                results = self.get_data_from_entity_api(since, to, entity_type)
                if results:
                    new_timestamp = datetime.fromisoformat(results[-1]["event_timestamp"].replace("Z", "+00:00")) + timedelta(seconds=1)
                    logger.info(f"[{__parser__}][execute] :: Successfully got {len(results)} '{entity_type}' logs, updating last_collected_timestamps['vectra_{entity_type}'] -> {new_timestamp}", extra={'frontend': str(self.frontend)})
                    self.last_collected_timestamps[f"vectra_{entity_type}"] = new_timestamp
                    logs.extend(results)
                elif since < timezone.now() - timedelta(hours=24):
                    self.last_collected_timestamps[f"vectra_{entity_type}"] = self.last_collected_timestamps[f"vectra_{entity_type}"] +timedelta(hours=1)
                self.update_lock()
                logs.extend(results)
                self.update_lock()
            except Exception as e:
                logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})

        # Send those lines to Rsyslog
        self.write_to_file([self.format_log(log) for log in logs])

        # And update lock after sending lines to Rsyslog
        self.update_lock()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})