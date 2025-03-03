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
__doc__ = 'Catonetworks API Parser toolkit'
__parser__ = 'CATONETWORKS'

import json
import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CatonetworksAPIError(Exception):
    pass


class CatonetworksParser(ApiParser):

    URL = "https://api.catonetworks.com/api/v1/graphql2"
    MAX_LOGS = 3000

    def __init__(self, data):
        super().__init__(data)

        self.catonetworks_api_key = data["catonetworks_api_key"]
        self.catonetworks_account_id = data["catonetworks_account_id"]

        self.marker = data.get("catonetworks_marker", "")
        self.event_filter_string = ""
        self.event_subfilter_string = ""

    def execute_query(self, query):
        data = {'query':query}
        headers = { 'x-api-key': self.catonetworks_api_key,'Content-Type':'application/json'}
        logger.info(f"[{__parser__}]:execute_query: URL: {self.URL}, data: {json.dumps(data).encode("ascii"),}", extra={'frontend': str(self.frontend)})
        response = requests.post(
            url=self.URL,
            data=json.dumps(data).encode("ascii"),
            headers=headers,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl,
            timeout=30
        )
        response.raise_for_status()
        result = response.json()

        return result

    def get_logs(self, retries=1):
        query = '''{
            eventsFeed(
                accountIDs: [''' + self.catonetworks_account_id + ''']
                marker: "''' + self.marker + '''"
                filters: [''' + self.event_filter_string + ',' + self.event_subfilter_string + ''']
            ) {
                marker
                fetchedCount
                accounts {
                    id
                    errorString
                    records {
                        time
                        fieldsMap
                    }
                }
            }
        }'''

        while retries > 0 and not self.evt_stop.is_set():
            try:
                result = self.execute_query(query)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as error:
                retries -= 1
                logger.warning(f"[{__parser__}]:execute_query: {error}", extra={'frontend': str(self.frontend)})
                if retries > 0:
                    logger.warning(f"[{__parser__}]:execute_query: waiting 20 seconds ({retries} tries remaining)", extra={'frontend': str(self.frontend)})
                    self.update_lock()
                    self.evt_stop.wait(20)
                continue
            except (requests.exceptions.JSONDecodeError, requests.exceptions.HTTPError) as error:
                logger.error(f"[{__parser__}]:execute_query: {error}", extra={'frontend': str(self.frontend)})
                raise CatonetworksAPIError(f"Error while getting logs. reason: {error}")

            if "errors" in result:
                logger.error(f"[{__parser__}]:execute_query: Error while getting logs. reason : {result['errors']}", extra={'frontend': str(self.frontend)})
                raise CatonetworksAPIError(f"Error while getting logs. reason : {result['errors']}")

            self.marker = result["data"]["eventsFeed"]["marker"]
            fetchedCount = int(result["data"]["eventsFeed"]["fetchedCount"])
            records = result["data"]["eventsFeed"]["accounts"][0]["records"]
            return fetchedCount, records

        logger.error(f"[{__parser__}]:execute_query: FATAL ERROR retry count exceeded", extra={'frontend': str(self.frontend)})
        raise CatonetworksAPIError("FATAL ERROR retry count exceeded")

    def test(self):
        try:
            _, logs = self.get_logs()
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

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        fetched_count = self.MAX_LOGS

        while fetched_count == self.MAX_LOGS and not self.evt_stop.is_set():
            try:
                fetched_count, logs = self.get_logs(retries=5)
            except Exception as e:
                logger.exception(f"[{__parser__}][get_logs]: {e}", extra={'frontend': str(self.frontend)})
                raise CatonetworksAPIError(e)
            # Downloading may take some while, so refresh token in Redis
            self.update_lock()
            if self.marker != "":
                self.frontend.catonetworks_marker = self.marker
            self.write_to_file([self.format_log(log) for log in logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        logger.info(f"[{__parser__}][execute]: Parsing done.", extra={'frontend': str(self.frontend)})