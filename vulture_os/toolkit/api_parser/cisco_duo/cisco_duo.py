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
__author__ = "Julien Pollet"
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'CISCO DUO API'
__parser__ = 'CISCO DUO'

import json
import logging
import hmac
import hashlib
import urllib.parse
import base64
import requests

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class CiscoDuoAPIError(Exception):
    pass

class CiscoDuoParser(ApiParser):

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    ENDPOINTS = ["authentication"]
    UNUSED_ENDPOINTS = ["activity", "telephony"]
    LIMIT = 1000

    PATH = "/admin/v2/logs/"

    def __init__(self, data):
        super().__init__(data)
        
        self.cisco_duo_host = data["cisco_duo_host"]
        self.cisco_duo_ikey = data["cisco_duo_ikey"]
        self.cisco_duo_skey = data["cisco_duo_skey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                self.session.headers.update(headers)

            return True

        except Exception as err:
            raise CiscoDuoAPIError(err)

    def __execute_query(self, hostname, path, query, timeout=20):

        self._connect()

        url = f"https://{hostname}{path}"
        headers = self.make_headers(hostname, path, query)

        msg = "URL : " + url + " Query : " + str(query)
        logger.info(f"[{__parser__}] Request API : {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=query,
            headers=headers,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )

        # Get json response
        if response.status_code == 200:
            logger.info(f"[{__parser__}]:execute_query: API Request Successfull", extra={'frontend': str(self.frontend)})
            return response.json()['response']
        # Errors
        elif response.status_code == 429:
            msg = "execute_query: API Request failed, we've hit the rate-limiting (code 429) -- this is 'intended' and had effects on log collection only on very high volumetry"
            logger.error(f"[{__parser__}]:{msg}", extra={'frontend': str(self.frontend)})
            raise CiscoDuoAPIError(msg)
        raise CiscoDuoAPIError(f"Error at Cisco Duo API Call URL: {url} Code: {response.status_code} Content: {response.content}")

    def make_headers(self, hostname, path, query=""):

        date_now = timezone.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        query_encoded = urllib.parse.urlencode(query)

        payload = date_now + '\n' \
            + 'GET' + '\n' \
            + hostname + '\n' \
            + path + '\n' \
            + query_encoded

        signature_digest = hmac.new(
            key=bytes(self.cisco_duo_skey, encoding="utf-8"),
            msg=bytes(payload, encoding="utf-8"),
            digestmod=hashlib.sha1
        ).hexdigest()

        auth = f"{self.cisco_duo_ikey}:{signature_digest}"
        auth_b64 = base64.b64encode(bytes(auth, encoding="utf-8")).decode()

        headers = {
            "Date": date_now,
            "Authorization": f'Basic {auth_b64}'
        }

        return headers

    def test(self):

        current_time = timezone.now()
        try:
            logs = self.get_logs(since=(current_time - timedelta(hours=24)), to=current_time, endpoint="authentication")

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

    def get_logs(self, since=None, to=None, endpoint=None):
        path = self.PATH + endpoint
        hostname = self.cisco_duo_host

        query = {}

        maxtime = int(to.timestamp() * 1000)
        mintime = int(since.timestamp() * 1000)

        query['limit'] = self.LIMIT

        query['maxtime'] = maxtime
        query['mintime'] = mintime
        query['sort'] = "ts:asc"

        return self.__execute_query(hostname, path, query)

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        for endpoint in self.ENDPOINTS:
            try:
                # delay log gathering for two minutes as API will return empty result otherwise in that range
                since = self.frontend.last_api_call
                to = min(timezone.now() - timedelta(minutes=2), since + timedelta(hours=24))
                if since >= to: since -= timedelta(minutes=2) # Ensure mintime<maxtime (for the first execution)

                # the reason we are not doing any iteration/pagnination in get_logs or here is because we can't get more than 1k logs and the API explicitly says that we must call it only 1 time/min (cf : https://duo.com/docs/adminapi#logs)
                response : dict = self.get_logs(since=since, to=to, endpoint=endpoint)

                if response.get("metadata"):
                    self.write_to_file([self.format_log(log) for log in response['authlogs']])
                    self.update_lock()
                    if next_offset := response['metadata'].get('next_offset'):
                        self.frontend.last_api_call = datetime.fromtimestamp(int(next_offset[0])/1000, tz=timezone.utc) # save this in case of failure
                        logger.info(f"[{__parser__}]:Updated last_api_call {self.frontend.last_api_call}", extra={'frontend': str(self.frontend)})

                logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

            except Exception as e:
                msg = f"Failed to get endpoint {endpoint}\n{e}"
                logger.exception(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
