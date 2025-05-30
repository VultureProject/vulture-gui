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
__doc__ = 'Blackberry Cylance API Parser'
__parser__ = 'BLACKBERRY CYLANCE'

import json
import jwt
import logging
import requests
import time
import uuid

from datetime import timedelta
from django.conf import settings
from django.utils import dateparse, timezone

from toolkit.api_parser.api_parser import ApiParser, EarlyTerminationWarning

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')



class BlackberryCylanceAPIError(Exception):
    pass


class BlackberryCylanceParser(ApiParser):
    AUTH_URI = "auth/v2/token"
    THREATS_URI = "threats/v2"       #URI pour les alertes AV

    HEADERS = {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json"
    }

    def __init__(self, data):
        """
            blackberry_cylance_host
            blackberry_cylance_tenant
            blackberry_cylance_app_id
            blackberry_cylance_app_secret
        """
        super().__init__(data)

        self.blackberry_cylance_host = data["blackberry_cylance_host"].rstrip("/")
        if not self.blackberry_cylance_host.startswith('https://'):
            self.blackberry_cylance_host = f"https://{self.blackberry_cylance_host}"

        self.blackberry_cylance_tenant = data["blackberry_cylance_tenant"]
        self.blackberry_cylance_app_id = data["blackberry_cylance_app_id"]
        self.blackberry_cylance_app_secret = data["blackberry_cylance_app_secret"]

        self.session = None



    def _connect(self, timeout=10):
        auth_url = f"{self.blackberry_cylance_host}/{self.AUTH_URI}"

        logger.info(f"[{__parser__}]:_connect: getting access token from {auth_url}", extra={'frontend': str(self.frontend)})
        logger.debug(f"[{__parser__}]:_connect: url -> {auth_url}, tenant -> {self.blackberry_cylance_tenant}, app_id -> {self.blackberry_cylance_app_id}, app_secret -> [masked], timeout -> {timeout}, proxies -> {self.proxies}", extra={'frontend': str(self.frontend)})

        token_expiration = 300 # Set token to expire after 5 minutes (documentation states token should only be used once, so 5 minutes should be more than enough for a single token/single batched fetch every minute)

        jwt_claims = {
            "iat": int(time.time()),
            "exp": (int(time.time()) + token_expiration),
            "iss": "http://cylance.com",
            "sub": self.blackberry_cylance_app_id,
            "tid": self.blackberry_cylance_tenant,
            "jti": str(uuid.uuid4())
        }

        encoded = jwt.encode(jwt_claims, self.blackberry_cylance_app_secret, algorithm='HS256')
        payload = {"auth_token": encoded}

        self.session = requests.session()
        self.session.headers.update(self.HEADERS)

        try:
            logger.info(f"[{__parser__}]:connect: URL: {auth_url}", extra={'frontend': str(self.frontend)})
            response = self.session.post(
                auth_url,
                json=payload,
                timeout=timeout,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        except requests.RequestException as e:
            self.session = None
            logger.error(f"[{__parser__}]:_connect: Could not get a valid token from APIs: {str(e)}", extra={'frontend': str(self.frontend)})
            raise BlackberryCylanceAPIError("Could not get a valid token from endpoint")

        if response.status_code not in [200,201]:
            self.session = None
            logger.error(f"[{__parser__}]:_connect: Authentication failed. code: {response.status_code}", extra={'frontend': str(self.frontend)})
            logger.debug(f"[{__parser__}]:_connect: Authentication failed. reason: {response.content}", extra={'frontend': str(self.frontend)})
            raise BlackberryCylanceAPIError(f"Authentication failed. code: {response.status_code}")

        try:
            ret = response.json()
            self.session.headers.update({"Authorization": f"Bearer {ret['access_token']}"})
        except Exception as e:
            logger.exception(e, extra={'frontend': str(self.frontend)})
            raise BlackberryCylanceAPIError("Error while getting access token from service's response")

        logger.info(f"[{__parser__}]:_connect: Successfuly got a new token, ready to request", extra={'frontend': str(self.frontend)})


    def _execute_query(self, method, url, query={}, timeout=10):
        """
        send a query to the Blackberry Cylance endpoint, using the access_token previously recovered in the session's headers
        """
        if not self.session:
            self._connect()

        logger.info(f"[{__parser__}]:_execute_query: sending request to {url}, with parameters {query}", extra={'frontend': str(self.frontend)})

        if method == "GET":
            try:
                response = self.session.get(
                    url,
                    params=query,
                    timeout=timeout,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                )

                if response.status_code == 429:
                    logger.warning(f"[{__parser__}]:_execute_query: API Request failed (code 429), stopping this run and waiting for the next", extra={'frontend': str(self.frontend)})
                    raise EarlyTerminationWarning("Rate limit exceeded")

                if response.status_code not in [200, 201]:
                    logger.error(f"[{__parser__}]:_execute_query: Error while getting logs. code: {response.status_code}", extra={'frontend': str(self.frontend)})
                    logger.debug(f"[{__parser__}]:_execute_query: Error while getting logs. reason: {response.content}", extra={'frontend': str(self.frontend)})
                    raise BlackberryCylanceAPIError(f"Error at blackberry Cylance API Call URL: {url} Code: {response.status_code}")

            except requests.RequestException as e:
                self.session = None
                logger.error(f"[{__parser__}]:_execute_query: Could not request endpoint: {str(e)}", extra={'frontend': str(self.frontend)})
                raise BlackberryCylanceAPIError("Could not get a valid token from endpoint")
        else:
            raise BlackberryCylanceAPIError(f"Error while requesting Blackberry Cylance, unknown method : {method}")

        return response.json()


    def _fetch_threat_details(self, threat):
        threat_details_url = f"{self.blackberry_cylance_host}/{self.THREATS_URI}/{threat['sha256']}"
        logger.debug(f"[{__parser__}]:_fetch_threat_details: querying details for threat {threat['sha256']}", extra={'frontend': str(self.frontend)})
        details = self._execute_query("GET", threat_details_url)
        return details


    def _fetch_threat_devices(self, threat):
        threat_devices_url = f"{self.blackberry_cylance_host}/{self.THREATS_URI}/{threat['sha256']}/devices"
        devices = []
        page = 0
        number_of_pages = 1

        logger.debug(f"[{__parser__}]:_fetch_threat_devices: querying devices for threat {threat['sha256']}", extra={'frontend': str(self.frontend)})

        while page < number_of_pages:
            page += 1
            query = {
                "page": page,
                "page_size": 100
            }
            ret = self._execute_query("GET", threat_devices_url, query=query)
            try:
                number_of_pages = ret['total_pages']
                devices.extend(ret['page_items'])
            except Exception as e:
                logger.error(f"[{__parser__}]:_fetch_threat_devices: could not extract number of pages and devices from response: {e}", extra={'frontend': str(self.frontend)})
                logger.debug(f"[{__parser__}]:_fetch_threat_devices: ret is {ret}", extra={'frontend': str(self.frontend)})
                raise BlackberryCylanceAPIError("Could not extract info while getting devices affected by a threat")

        return devices



    def _fetch_threats(self, start_time, end_time, page=1, page_size=100):
        threats_url = f"{self.blackberry_cylance_host}/{self.THREATS_URI}"
        threats = []
        query = {
            "page": page,
            "page_size": page_size,
            "start_time": start_time.isoformat().replace("+00:00", "Z"),
            "end_time": end_time.isoformat().replace("+00:00", "Z"),
        }

        logger.info(f"[{__parser__}]:_fetch_threats: querying threats from {start_time} to {end_time}, page {page}", extra={'frontend': str(self.frontend)})

        ret = self._execute_query("GET", threats_url, query=query)
        try:
            number_of_pages = ret['total_pages']
            threats = ret['page_items']
        except Exception as e:
            logger.error(f"[{__parser__}]:_fetch_threats: could not extract number of pages and threats from response: {e}", extra={'frontend': str(self.frontend)})
            logger.debug(f"[{__parser__}]:_fetch_threats: ret is {ret}", extra={'frontend': str(self.frontend)})
            raise BlackberryCylanceAPIError("Could not extract threats from response")

        return number_of_pages, threats


    def _get_complete_threats(self, start_time, end_time, page=1, page_size=100):
        number_of_pages, threats = self._fetch_threats(start_time, end_time, page, page_size)

        for threat in threats:
            details = self._fetch_threat_details(threat)
            devices = self._fetch_threat_devices(threat)

            threat.update(details)
            threat['nb_assets_affected'] = len(devices)
            logger.debug(f"[{__parser__}]:_get_complete_threats: {len(devices)} affected devices for threat {threat['sha256']}", extra={'frontend': str(self.frontend)})

            if threat['nb_assets_affected'] == 1:
                threat['device'] = devices[0]
            else:
                for device in devices:
                    if device['date_found'] == threat['last_found']:
                        threat['device'] = device

        return number_of_pages, threats


    def _format_log(self, log):
        if "date" in log:
            # parse datetime using django utils to strictly format the output
            parsed_date = dateparse.parse_datetime(log['last_found']).replace(tzinfo=timezone.utc)
            if parsed_date:
                log["last_found"] = parsed_date.isoformat().replace("+00:00", ".000Z")
        return log


    def execute(self):
        """
            Central function to fetch logs
        """
        # the API gets data with a minimal precision of 10 milliseconds (from manual tests),
        # so avoid getting the same alert twice by incrementing start_time by 10 milliseconds
        start_time = self.last_api_call + timedelta(milliseconds=10)
        # Get at most a batch of 24h, to avoid running the parser for too long
        end_time = min(timezone.now(), start_time + timedelta(hours=24))

        number_of_logs = 0
        page = 0
        number_of_pages = 1

        while page < number_of_pages:
            page += 1
            number_of_pages, threats = self._get_complete_threats(start_time, end_time, page)
            data = [self._format_log(threat) for threat in threats]
            number_of_logs += len(data)
            # Writting may take a while, so refresh token in Redis
            self.update_lock()
            self.write_to_file([json.dumps(line) for line in data])

        if number_of_logs != 0:
            self.frontend.last_api_call = end_time
            self.frontend.save(update_fields=['last_api_call'])
        elif self.last_api_call < timezone.now()-timedelta(hours=24):
            # If no logs where retrieved during the last 24hours,
            # move forward 1h to prevent stagnate ad vitam eternam
            self.frontend.last_api_call += timedelta(hours=1)
            self.frontend.save(update_fields=['last_api_call'])

        logger.info(f"[{__parser__}]:execute: Got {number_of_logs} lines", extra={'frontend': str(self.frontend)})
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})


    def test(self):
        logger.info(f"[{__parser__}]:test: Launching test", extra={'frontend': str(self.frontend)})

        end_time = timezone.now()
        start_time = end_time - timedelta(days=30)

        logger.info(f"[{__parser__}]:test: start_time: {start_time}, end_time: {end_time}", extra={'frontend': str(self.frontend)})

        try:
            # Only get 10 logs in first page
            _, results = self._get_complete_threats(start_time, end_time, 1, 10)

            return {
                "status": True,
                "data": results
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
