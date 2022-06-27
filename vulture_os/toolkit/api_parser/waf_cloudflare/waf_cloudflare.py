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

import json
import logging
import requests

from datetime import datetime, timezone, timedelta
from django.conf import settings
from django.utils import dateparse
import time

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
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Bearer {self.waf_cloudflare_apikey}"})



    def get_logs(self, logs_from=None, logs_to=None, test=False):
        self.__connect()

        url = f"https://api.cloudflare.com/client/v4/zones/{self.waf_cloudflare_zoneid}/logs/received"
        query = {}
        if logs_from:
            query.update({'start': logs_from.strftime('%Y-%m-%dT%H:%M:%SZ')})
        if logs_to:
            query.update({'end': logs_to.strftime('%Y-%m-%dT%H:%M:%SZ')})

        query.update({"fields":"EdgeStartTimestamp,BotScore,BotScoreSrc,BotTags,ClientDeviceType,ClientIP,ClientIPClass,ClientRequestBytes,ClientRequestHost,ClientRequestMethod,ClientRequestPath,ClientRequestProtocol,ClientRequestReferer,ClientRequestScheme,ClientRequestSource,ClientRequestURI,ClientRequestAgent,ClientSSIProtocol,ClientSrcPort,ClientXRequestedWith,Cookies,FirewallMatchesActions,FirewallMatchesSources,OriginIP,OriginResponseBytes,OriginResponseStatus,OriginSSLProtocol,RequestHeaders,ResponseHeaders,SecurityLevel,WAFAction,WAFRuleID,WAFRuleMessage,ZoneName"})

        logger.debug(f"{[__parser__]}:get_logs: params for request are {query}", extra={'frontend': str(self.frontend)})


        response = self.session.get(url, params=query)
        response.raise_for_status()
        content = response.text.split("\n")[:-1]

        logger.info(f"{[__parser__]}:get_logs: got {len(content)} new lines", extra={'frontend': str(self.frontend)})
        return content


    def execute(self):
        # Aware UTC datetime
        current_time = datetime.now(timezone.utc)
        since = self.last_api_call
        if (self.last_api_call is None) or (datetime.now(timezone.utc) - self.last_api_call >= timedelta(seconds=62)):
            since = (datetime.now(timezone.utc) - timedelta(seconds=62))
        #The API has a delay of 60 seconds
        to = current_time - timedelta(seconds=60)
        logs = self.get_logs(logs_from=since, logs_to=to)
        self.update_lock()
        # increment by 1ms to avoid repeating a line if its timestamp happens to be the exact timestamp 'to'
        self.last_api_call = to + timedelta(microseconds=1000)
        self.write_to_file(logs)

        logger.info(f"{[__parser__]}:execute: Parsing done.", extra={'frontend': str(self.frontend)})


    def test(self):
        current_time = datetime.now(timezone.utc)
        try:
            logs = self.get_logs(logs_from=(current_time - timedelta(seconds=62)), logs_to=(current_time - timedelta(seconds=61)))

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
