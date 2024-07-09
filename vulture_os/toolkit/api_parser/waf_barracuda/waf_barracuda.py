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
__credits__ = ["Kevin Guillemot", "Théo Bertin"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'WAF BARRACUDA API'
__parser__ = 'WAF BARRACUDA'

import json
import logging
import requests

from datetime import timedelta, datetime
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
        self.__connect()
        logger.debug(f"{[__parser__]}:__execute_query: querying '{url}' with parameters '{query}'", extra={'frontend': str(self.frontend)})
        response = self.session.get(url,
            params=query,
            headers=self.HEADERS,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != 200:
            raise WAFBarracudaAPIError(f"{[__parser__]}:get_logs: Status code = {response.status_code}, Error = {response.text}")
        else:
            return response.json()


    def get_applications(self):
        app_ids = []
        url = f"https://{self.WAF_BARRACUDA_HOST}/v2/waasapi/applications/"
        page = 1
        reply = self.__execute_query(url, query={"page": page})
        logger.debug(f"{[__parser__]}:get_applications: got {reply['count']} applications", extra={'frontend': str(self.frontend)})
        app_ids.extend([app.get("id") for app in reply.get("results", [])])
        while reply.get('count', 0) > len(app_ids):
            page += 1
            reply = self.__execute_query(url, query={"page": page})
            app_ids.extend([app.get("id") for app in reply.get("results", [])])
        return app_ids


    def get_logs(self, app_id, log_type, since, to, page):
        url = f"https://{self.WAF_BARRACUDA_HOST}/v2/waasapi/applications/{app_id}/{log_type}/logs"
        query = {
            "from": since.timestamp(),
            "to": to.timestamp(),
            "itemsPerPage": "1000",
            "page": page,
            "sortingType": "timestamp",
            "sortingDirection": "asc"
        }

        logger.debug(f"{[__parser__]}:get_logs: params for {log_type} logs request of application {app_id} are {query}", extra={'frontend': str(self.frontend)})
        data = self.__execute_query(url, query=query)
        logger.info(f"{[__parser__]}:get_logs: got {int(data['count'])} {log_type} logs from application {app_id}", extra={'frontend': str(self.frontend)})

        return data


    def test(self):
        try:
            app_ids = self.get_applications()
            since = timezone.now() - timedelta(hours=12)
            to = timezone.now()
            results = { 'count': 0,
                        'apps': app_ids,
                        'since': since,
                        'to': to,
                        'sample': []}
            for log_type in ['access', 'waf']:
                data = self.get_logs(app_id=app_ids[0], log_type=log_type, since=since, to=to, page=1)
            results['count'] += int(data['count'])
            results['sample'].extend(data['results'])

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


    def format_log(self, log):
        return json.dumps(log)


    def execute(self):
        app_ids = []
        logger.info(f"[{__parser__}]:execute: getting the list of available applications", extra={'frontend': str(self.frontend)})
        try:
            app_ids = self.get_applications()
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: could not get the list of available applications: {e}", extra={'frontend': str(self.frontend)})

        for app_id in app_ids:
            for log_type in ['access', 'waf']:
                timestamp_field_name = f"app{app_id}_{log_type}"

                # Stop collector if asked nicely
                if self.evt_stop.is_set():
                    break

                try:
                    self.update_lock()
                    since = self.last_collected_timestamps.get(timestamp_field_name) or (timezone.now() - timedelta(days=1))
                    to = min(timezone.now(), since + timedelta(hours=24))

                    page = 1
                    logs = []

                    logger.info(f"[{__parser__}]:execute: getting {log_type} logs from {since} to {to}, for application {app_id}", extra={'frontend': str(self.frontend)})
                    data = self.get_logs(app_id, log_type, since, to, page)
                    logger.debug(f"{[__parser__]}:execute: must fetch {int(data['count'])} {log_type} logs from application {app_id}", extra={'frontend': str(self.frontend)})
                    logs.extend(data['results'])
                    while int(data['count']) > len(logs) and not self.evt_stop.is_set():
                        self.update_lock()
                        page += 1
                        logger.debug(f"{[__parser__]}:execute: page {page}", extra={'frontend': str(self.frontend)})
                        data = self.get_logs(app_id, log_type, since, to, page)
                        logs.extend(data['results'])
                        logger.debug(f"{[__parser__]}:execute: {len(logs)} logs in cache", extra={'frontend': str(self.frontend)})

                    self.write_to_file([self.format_log(l) for l in logs])
                    self.update_lock()

                    # API doesn't give more than 10 pages (10k logs) by call
                    if page > 10:
                        # logs are ordered, so last one is most recent
                        real_to = logs[-1].get("logData_EpochTime")
                        if real_to:
                            to = datetime.fromtimestamp(int(real_to)/1000, tz=timezone.utc)

                    self.last_collected_timestamps[timestamp_field_name] = to + timedelta(microseconds=1000)
                except Exception as e:
                    logger.exception(f"[{__parser__}]:execute: error while trying to handle {log_type} logs for application {app_id}: {e}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
