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
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Apex API Parser'
__parser__ = 'APEX'

import logging
import requests
import base64
import jwt
import hashlib

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ApexAPIError(Exception):
    pass


class ApexParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.apex_server_host = data["apex_server_host"]
        if not self.apex_server_host.startswith('https://'):
            self.apex_server_host = f"https://{self.apex_server_host}"
        self.apex_application_id = data["apex_application_id"]
        self.apex_api_key = data["apex_api_key"]

        self.session = None
        self.HEADERS = {'Content-Type': 'application/json;charset=utf-8'}
        self.canonicalRequestHeaders = ''
        self.useRequestBody = ''

    def create_checksum(self, http_method, raw_url, headers, request_body):
        string_to_hash = http_method.upper() + '|' + raw_url.lower() + '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

    def create_jwt_token(self, application_id, api_key, http_method, raw_url, headers, request_body,
        iat, algorithm='HS256', version='V1'):
        payload = {'appid': application_id,
               'iat': iat,
               'version': version,
               'checksum': self.create_checksum(http_method, raw_url, headers, request_body)}
        token = jwt.encode(payload, api_key, algorithm=algorithm)
        return token

    def _connect(self, raw_url):
        try:
            # New session because timeout is very short
            self.session = requests.Session()
            jwt_token = self.create_jwt_token(self.apex_application_id, self.apex_api_key, 'GET',
                              raw_url,
                              self.canonicalRequestHeaders, self.useRequestBody, iat=timezone.now().timestamp())
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({'Authorization': 'Bearer ' + jwt_token })

            return True

        except Exception as err:
            raise ApexAPIError(err)

    def test(self):
        start_time = timezone.now() - timedelta(days=1)
        try:
            status, logs, _, _ = self.get_logs_with_timestamp("pattern_updated_status", start_time)

            if not status:
                return {
                    "status": False,
                    "error": logs
                }

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def execute_query(self, url, timeout=60):

        logger.info(f"[{__parser__}]:execute_query: URL: {url}", extra={'frontend': str(self.frontend)})
        response = self.session.get(
            url,
            proxies=self.proxies,
            timeout=timeout,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )
        if response.status_code != 200:
            error = f"Error at Apex API Call: status : {response.status_code}, content : {response.content}"
            logger.error(f"[{__parser__}]:execute_query: {error}", extra={'frontend': str(self.frontend)})
            raise ApexAPIError(error)

        return response.json()


    def get_logs_with_timestamp(self, kind, since):

        url_path = f"/WebApp/api/v1/Logs/{kind}?output_format=CEF&since_time={int(since.timestamp())}"
        logs = []
        try:
            while True:
                self._connect(url_path)
                content = self.execute_query(self.apex_server_host + url_path)
                if data_logs := content["Data"]["Logs"]:
                    logs.extend(data_logs)
                if next_url := content["Data"].get("Next"):
                    url_path = f"/WebApp/api/v1/Logs/{kind}" + next_url[next_url.index("?"):]
                else:
                    break
            next_timestamp = int(content["Data"]["NextPage"]["SinceTime"])
            next_page_token = int(content["Data"]["NextPage"]["PageToken"])

        except Exception as e:
            raise ApexAPIError(e)
        return True, logs, next_page_token, next_timestamp

    def get_logs_with_page_token(self, kind, page_token):

        url_path = f"/WebApp/api/v1/Logs/{kind}?output_format=CEF&page_token={page_token}"
        logs = []
        try:
            while True:
                self._connect(url_path)
                content = self.execute_query(self.apex_server_host + url_path)
                if data_logs := content["Data"]["Logs"]:
                    logs.extend(data_logs)
                if next_url := content["Data"].get("Next"):
                    url_path = f"/WebApp/api/v1/Logs/{kind}" + next_url[next_url.index("?"):]
                else:
                    break
            next_page_token = int(content["Data"]["NextPage"]["PageToken"])

        except Exception as e:
            raise ApexAPIError(e)
        return True, logs, next_page_token


    def execute(self):
        log_kinds_page_token = ["data_loss_prevention", "device_access_control", "behaviormonitor_rule", "officescan_virus", "spyware", "web_security", "security", "ncie", "cncdetection", "filehashdetection", "Predictive_Machine_Learning", "Sandbox_Detection_Log", "EACV_Information", "Managed_Product_Logged_Information", "Attack_Discovery_Detections", "product_auditing_events", "intrusion_prevention"]
        log_kinds_timestamp = ["pattern_updated_status", "engine_updated_status"]
        for kind in log_kinds_page_token:
            logger.info(f"[{__parser__}]:execute: Getting {kind}", extra={'frontend': str(self.frontend)})
            if f"apex_{kind}_page_token" in self.frontend.apex_page_token.keys():
                page_token = self.frontend.apex_page_token[f"apex_{kind}_page_token"]
                status, logs, next_page_token = self.get_logs_with_page_token(kind, page_token)
            else:
                if f"apex_{kind}_timestamp" in self.frontend.apex_timestamp.keys():
                    since = datetime.fromtimestamp(self.frontend.apex_timestamp[f"apex_{kind}_timestamp"])
                else:
                    since = (timezone.now() - timedelta(hours=24))
                status, logs, next_page_token, next_timestamp = self.get_logs_with_timestamp(kind, since)

            if not status:
                raise ApexAPIError(logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()
            self.write_to_file(logs)
            # Writting may take some while, so refresh token in Redis
            self.update_lock()
            if len(logs) > 0:
                try:
                    self.frontend.apex_page_token[f"apex_{kind}_page_token"] = next_page_token
                    self.frontend.save(update_fields=['apex_page_token'])
                except Exception as err:
                    logger.error(f"[{__parser__}]:execute: {err}",
                                 extra={'frontend': str(self.frontend)})
        for kind in log_kinds_timestamp:
            logger.info(f"[{__parser__}]:execute: Getting {kind}", extra={'frontend': str(self.frontend)})
            if f"apex_{kind}_timestamp" in self.frontend.apex_timestamp.keys():
                since = datetime.fromtimestamp(self.frontend.apex_timestamp[f"apex_{kind}_timestamp"])
            else:
                since = (timezone.now() - timedelta(hours=24))
            status, logs, next_page_token, next_timestamp = self.get_logs_with_timestamp(kind, since)

            if not status:
                raise ApexAPIError(logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()
            self.write_to_file(logs)
            # Writting may take some while, so refresh token in Redis
            self.update_lock()
            if len(logs) > 0:
                try:
                    self.frontend.apex_timestamp[f"apex_{kind}_timestamp"] = next_timestamp
                    self.frontend.save(update_fields=['apex_timestamp'])
                except Exception as err:
                    logger.error(f"[{__parser__}]:execute: {err}",
                                 extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
