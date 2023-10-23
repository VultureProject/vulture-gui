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
import requests
import json
from datetime import datetime, timedelta
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

        self.access_token = None
        self.expires_in = None
        self.session = None

    def auth_token(self):

        res = {}

        logger.info("Generating access token.")
        url = self.vectra_host + self.TOKEN_ENDPOINT
        try:
            res = requests.post(
                url,
                auth=(self.vectra_client_id , self.vectra_secret_key ),
                data={"grant_type": "client_credentials"},
                timeout=30,
                headers = {"Content-Type": "application/x-www-form-urlencoded"},
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
            if res.status_code == 401:
                raise VectraAPIError(f"Status-code {res.status_code} Exception: Client ID or Client Secret is incorrect.")
            if res.status_code == 429:
                raise VectraAPIError("Too many requests.")
            res.raise_for_status()
            logger.info("Access token is generated.")

            return res.json().get("access_token"), res.json().get('expires_in')
            
        except Exception as e:
            logger.error(f"An exception occurred: {e} response: {res.status_code}")

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                
                self.session.headers.update(headers)
                self.session.headers.update({"Authorization": f"Bearer {self.access_token}"})

            return True

        except Exception as err:
            raise VectraAPIError


    def get_data_from_entity_api(self, query = {}):

        url = f"{self.vectra_host.strip().strip('/')}/api/v3.3/events/entity_scoring"
        types = [
            "account",
            "host"
        ]
        for typ in types:
            logger.info(f"Executing Entity {typ} API task.")
            query.update({"type": typ})
            response = self.session.get(
                url,
                params=query,
                timeout=20,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )

            # Other error
            if response.status_code != 200:
                raise VectraAPIError(
                    f"Error at Vectra API Call URL: {url} Code: {response.status_code} Content: {response.content}, Headers: {self.session.headers}, Query: f{query}")
            
            results = response.json()["events"]
            if response.json()["next_checkpoint"]:
                query.update({"from": response.json()["next_checkpoint"]})
                response = self.session.get(
                    url,
                    params=query,
                    timeout=20,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                )
                results += response.json()["events"]
        return results

        
    def get_logs(self, since=None, to=None):

        if self.expires_in is None or self.expires_in < timezone.now():
            access_token, expires_in = self.auth_token()
            self.access_token = access_token
            self.expires_in = timezone.now() + timedelta(seconds=expires_in)

        query = {"event_timestamp_gte": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "event_timestamp_lte": to.strftime("%Y-%m-%dT%H:%M:%SZ")}
        results = []
        for endpoint in ["api/v3.3/events/detections"]:
            response = self.__execute_query(query, endpoint)
            results += response["events"]
        results += self.get_data_from_entity_api(query)
        logger.info(f"results: {results}")
        return results

    def __execute_query(self, query, endpoint, timeout=20):

        self._connect()

        url = self.vectra_host + endpoint

        msg = "URL : " + url + " Query : " + str(query)
        logger.info(f"[{__parser__}] Request API : {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=query,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )

        # Other error
        if response.status_code != 200:
            raise VectraAPIError(
                f"Error at Vectra API Call URL: {url} Code: {response.status_code} Content: {response.content}, Headers: {self.session.headers}, Query: f{query}")
        
        return response.json()
    
    def format_log(log):
        return json.dumps(log)

     
    def test(self):
        logger.info(f"[{__parser__}]:test: Launching test", extra={'frontend': str(self.frontend)})

        try:
            self.expires_in = None
            since = timezone.now() - timedelta(hours=24)
            to = timezone.now()
            result = self.get_logs(since, to)

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

    def execute(self):
        try:
            ## GET LOGS ##
            since = self.frontend.last_api_call or (timezone.now() - timedelta(days=1))
            to = min(timezone.now(), since + timedelta(hours=24))
            
            logger.info(f"[{__parser__}]: get_logs since {since} to {to}", extra={'frontend': str(self.frontend)})
            results = self.get_logs(since, to)
            
            self.update_lock()
            self.frontend.last_api_call = to
            
            # Send those lines to Rsyslog
            logger.info(f"Logs: {results}")
            self.write_to_file([self.format_log(l) for l in results])
            # And update lock after sending lines to Rsyslog
            self.update_lock()
            self.frontend.save()
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})