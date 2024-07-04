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
__doc__ = 'WAF BARRACUDA API'
__parser__ = 'WAF BARRACUDA'

import json
import logging
import requests

from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class WAFBarracudaAPIError(Exception):
    pass

class WAFBarracudaParser(ApiParser):

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }
    WAF_BARRACUDA_HOST = "api.waas.barracudanetworks.com"

    def __init__(self, data):
        super().__init__(data)

        self.waf_barracuda_token = data["waf_barracuda_token"]

        self.session = None

    def __connect(self):

        if not self.session:
            self.session = requests.Session()
            self.session.proxies = self.proxies
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Bearer {self.waf_barracuda_token}"})

    def __execute_query(self, url, query={}, timeout=15):
        response = self.session.get(url,
            params=query,
            headers=self.HEADERS,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )
        if response.status_code != 200:
            raise WAFBarracudaAPIError(f"{[__parser__]}:get_logs: Status code = {response.status_code}, Error = {response.text}")
        else:
            return response.json()

    def get_logs(self, since, to):
        self.__connect()
        result = []
        #itemsPerPage max is 1000
        query = {"from": since.timestamp(), "to": to.timestamp(), "itemsPerPage": "1000", "sortingType": "timestamp", "sortingDirection": "asc"}
        url = f"https://{self.WAF_BARRACUDA_HOST}/v2/waasapi/applications/"
        applications = self.__execute_query(url)
        app_ids = [app.get("id") for app in applications.get("results")]
        for app_id in app_ids:
            page = 1
            query["page"] = page
            url = f"https://{self.WAF_BARRACUDA_HOST}/v2/waasapi/applications/{app_id}/access/logs"
            logger.debug(f"{[__parser__]}:get_logs: params for access logs request of application {app_id} are {query}", extra={'frontend': str(self.frontend)})
            data = self.__execute_query(url, query=query)
            logger.debug(f"{[__parser__]}:get_logs: {int(data['count'])} access logs from application {app_id}", extra={'frontend': str(self.frontend)})
            result.extend(data["results"])
            while int(data["count"]) > 1000 * page:
                page += 1
                query["page"] = page
                logger.debug(f"{[__parser__]}:get_logs: params for access logs request of application {app_id} are {query}", extra={'frontend': str(self.frontend)})
                data = self.__execute_query(url, query=query)
                result.extend(data["results"])
            page = 1
            query["page"] = page
            url = f"https://{self.WAF_BARRACUDA_HOST}/v2/waasapi/applications/{app_id}/waf/logs"
            logger.debug(f"{[__parser__]}:get_logs: params for waf logs request of application {app_id} are {query}", extra={'frontend': str(self.frontend)})
            data = self.__execute_query(url, query=query)
            logger.debug(f"{[__parser__]}:get_logs: {int(data['count'])} waf logs from application {app_id}", extra={'frontend': str(self.frontend)})
            result.extend(data["results"])
            while int(data["count"]) > 1000 * page:
                page += 1
                query["page"] = page
                logger.debug(f"{[__parser__]}:get_logs: params for waf logs request of application {app_id} are {query}", extra={'frontend': str(self.frontend)})
                data = self.__execute_query(url, query=query)
                result.extend(data["results"])
            
        return result

    def test(self):
        try:
            result = self.get_logs(timezone.now()-timedelta(hours=12), timezone.now())

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

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        try:
            since = self.frontend.last_api_call or (timezone.now() - timedelta(days=1))
            to = min(timezone.now(), since + timedelta(hours=24))

            logger.info(f"[{__parser__}]:execute: getting logs from {since} to {to}", extra={'frontend': str(self.frontend)})
            results = self.get_logs(since, to)
            self.update_lock()

            self.write_to_file([self.format_log(l) for l in results])
            self.update_lock()
            # increment by 1ms to avoid duplication of logs with timestamp equal to 'to'
            self.frontend.last_api_call = to + timedelta(microseconds=1000)
            self.frontend.save()
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
