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
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'WAF CLOUD PROTECTOR API'
__parser__ = 'WAF CLOUD PROTECTOR'

import json
import logging
import time
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


class WAFCloudProtectorAPIError(Exception):
    pass


class WAFCloudProtectorParser(ApiParser):

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.waf_cloud_protector_host = data["waf_cloud_protector_host"]
        self.waf_cloud_protector_api_key_pub = data["waf_cloud_protector_api_key_pub"]
        self.waf_cloud_protector_api_key_priv = data["waf_cloud_protector_api_key_priv"]
        self.waf_cloud_protector_provider = data["waf_cloud_protector_provider"]
        self.waf_cloud_protector_tenant = data["waf_cloud_protector_tenant"]
        self.waf_cloud_protector_servers = data["waf_cloud_protector_servers"]

        self.waf_cloud_protector_host = self.waf_cloud_protector_host.replace("https://", "").replace("http://", "")

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                # headers.update({'Authorization': self.proofpoint_trap_apikey})

                self.session.headers.update(headers)

            return True

        except Exception as err:
            raise WAFCloudProtectorAPIError(err)

    def __execute_query(self, url, headers=None, query=None, timeout=20):

        self._connect()

        msg = "URL : " + url + " Query : " + str(query) + " Headers : " + str(headers) 
        logger.info(f"[{__parser__}] Request API : {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=query,
            headers=headers,
            timeout=timeout,
            proxies=self.proxies,
            verify=False
        )

        # handler rate limit exceeding
        if response.status_code == 429:
            logger.info(f"[{__parser__}]:execute: API Rate limit exceeded, waiting 10 seconds...", extra={'frontend': str(self.frontend)})
            time.sleep(10)
            return self.__execute_query(url, query, timeout)
        elif response.status_code != 200:
            raise WAFCloudProtectorAPIError(
                f"Error at WAF CloudProtector API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json() 


    def make_request(self, host_url, log_type, server, query_encoded=""):

        # uri = "/logs/"+ log_type + "/" + self.waf_cloud_protector_provider + "/" + self.waf_cloud_protector_tenant + '/' + server
        uri = "/helpers/api"
        url = host_url + uri

        epoch = str(datetime.now().timestamp()).replace(".", "")[:-3]
        # epoch = str(int(time.time() * 1000))

        payload = f"""GET
        {self.waf_cloud_protector_host}
        /latest{uri}
        {self.waf_cloud_protector_api_key_pub}
        {epoch}
        {query_encoded}
        """
        signature_digest = hmac.new(
            key=self.waf_cloud_protector_api_key_priv.encode("utf8"),
            msg=payload.encode("utf8"),
            digestmod=hashlib.sha256
        ).digest() 
        signature = base64.b64encode(signature_digest).decode()

 
        headers = {
            "Accept": "application/json",
            "Host": self.waf_cloud_protector_host,
            "Authorization": f'DAAUTH apikey="{self.waf_cloud_protector_api_key_pub}", epoch="{epoch}", signature="{signature}"'    
        }
        return url, headers

    def test(self):

        current_time = timezone.now()
        try:
            logs = self.get_logs(since=(current_time - timedelta(hours=24)), nb_days=1, log_type="traffic", server=self.waf_cloud_protector_servers.split(',')[0])

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

    def get_logs(self, since=None, nb_days=1, log_type="alert", server=None):

        host_url = "https://" + self.waf_cloud_protector_host + "/latest"

        query = {}
        # query['limit'] = 1
        # query['start_date'] = since.strftime("%Y-%m-%d")
        query_encoded = urllib.parse.urlencode(query)

        url, headers = self.make_request(host_url, log_type, server, query_encoded)

        return self.__execute_query(url, headers, query)

    def execute(self):

        since = self.frontend.last_api_call or (timezone.now() - timedelta(days=30))

        # fetch at most 24h of logs to avoid the process running for too long
        to = min(timezone.now(), since + timedelta(hours=24))

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        response = self.get_logs(since, to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        logger.info(f"[{__parser__}]: GET LOG OK", extra={'frontend': str(self.frontend)})

        # for server in self.waf_cloud_protector_servers.split(','):

        for incident_log in response:

            formated_incident_log = self.format_incidents_logs(incident_log)
            alert_logs = formated_incident_log['events']

            self.write_to_file([self.format_alerts_logs(log) for log in alert_logs])
            
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        # update last_api_call only if logs are retrieved
        self.frontend.last_api_call = to + timedelta(seconds=1)

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
