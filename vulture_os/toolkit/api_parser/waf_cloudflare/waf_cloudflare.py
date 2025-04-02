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
__author__ = "gparain"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Waf Cloudflare API Parser'
__parser__ = 'WAF CLOUDFLARE'

import logging
from json import JSONDecodeError

import requests

from datetime import timedelta
from django.conf import settings
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class WAFCloudflareAPIError(Exception):
    pass


class WAFCloudflareParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
    }

    def __init__(self, data):
        """
            waf_cloudflare_zoneid
            waf_cloudflare_apikey

        """
        super().__init__(data)

        self.waf_cloudflare_zoneid = data["waf_cloudflare_zoneid"]
        self.waf_cloudflare_apikey = data["waf_cloudflare_apikey"]
        self.session = None

    def __connect(self):

        if self.session is None:
            self.session = requests.Session()
            self.session.proxies = self.proxies
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Bearer {self.waf_cloudflare_apikey}"})

    def _get_allowed_fields(self):
        reply = self.session.get(
            f"https://api.cloudflare.com/client/v4/zones/{self.waf_cloudflare_zoneid}/logs/received/fields")
        if reply.status_code != 200:
            logger.error(f"[{__parser__}]:_get_allowed_fields: Status code = {reply.status_code}, Error = {reply.text}",
                        extra={'frontend': str(self.frontend)})
            raise WAFCloudflareAPIError(f"[{__parser__}]: Could not get the list of allowed fields")
        try:
            return reply.json().keys()
        except JSONDecodeError as e:
            logger.error(f"[{__parser__}]:_get_allowed_fields: An error occurred when parsing the JSON response",
                         extra={'frontend': str(self.frontend)})
            raise WAFCloudflareAPIError(
                f"[{__parser__}]: Could not get the list of allowed fields"
            ) from e

    def get_logs(self, logs_from=None, logs_to=None):
        self.__connect()

        url = f"https://api.cloudflare.com/client/v4/zones/{self.waf_cloudflare_zoneid}/logs/received"
        query = {}
        if logs_from:
            query['start'] = logs_from.strftime('%Y-%m-%dT%H:%M:%SZ')
        if logs_to:
            query['end'] = logs_to.strftime('%Y-%m-%dT%H:%M:%SZ')

        query['fields'] = ",".join(self._get_allowed_fields())

        cpt = 0
        bulk = []
        logger.info(f"[{__parser__}]:get_logs: URL: {url} , params: {query}", extra={'frontend': str(self.frontend)})
        with self.session.get(
            url,
            params=query,
            proxies=self.proxies,
            stream=True,
            verify=self.api_parser_verify_ssl) as reply:
            if reply.status_code != 200:
                logger.error(f"[{__parser__}]:get_logs: Status code = {reply.status_code}, Error = {reply.text}",
                        extra={'frontend': str(self.frontend)})
                raise WAFCloudflareAPIError(f"[{__parser__}]: Error while fetching logs, API returned a {reply.status_code}")
            for line in reply.iter_lines():
                if not line:
                    continue
                try:
                    bulk.append(line.decode('utf8'))
                except UnicodeDecodeError:
                    logger.warning(f"[{__parser__}]:get_logs: Error while trying to decode a log line",
                            extra={'frontend': str(self.frontend)})
                    logger.debug(f"[{__parser__}]:get_logs: Log line -> {line}",
                            extra={'frontend': str(self.frontend)})
                    pass
                cpt += 1
                if len(bulk) == 10000:
                    yield bulk
                    bulk = []

        logger.info(f"[{__parser__}]:get_logs: got {cpt} new lines", extra={'frontend': str(self.frontend)})
        yield bulk

    def execute(self):
        # Aware UTC datetime
        current_time = timezone.now()
        since = self.frontend.last_api_call or (timezone.now() - timedelta(hours=24))
        # Start cannot exceed a time in the past greater than seven days.
        if since < (current_time - timedelta(hours=167)):
            logger.info(f"[{__parser__}]:execute: Since is older than 167h, resetting-it to 167h in the past",
                        extra={'frontend': str(self.frontend)})
            since = current_time - timedelta(hours=167)

        # Difference between start and end must not be greater than one hour.
        to = since + timedelta(hours=1)

        # end must be at least five (ONE (doc is invalid) minutes earlier than now
        if to > (current_time - timedelta(minutes=1)):
            to = current_time - timedelta(minutes=1)

        msg = f"Parser starting from {since} to {to}."
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        try:
            for logs in self.get_logs(logs_from=since, logs_to=to):
                self.update_lock()
                self.write_to_file(logs)
            # from is inclusive, to is exclusive
            self.frontend.last_api_call = to
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: {str(e)}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

    def test(self):
        # Query 30 seconds of logs, starting from 24 hours ago
        # To prevent, for instance, UTC-10 missing logs
        current_time = timezone.now()
        try:
            logs = list(self.get_logs(logs_from=(current_time - timedelta(hours=24, seconds=31)),
                                      logs_to=(current_time - timedelta(hours=24, seconds=1))))

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {str(e)}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
