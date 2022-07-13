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
__author__ = "Nicolas Lançon"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Sophos Cloud API Parser'
__parser__ = 'SOPHOS CLOUD'

import json
import logging
import requests

from datetime import datetime, timedelta, timezone
from dateutil.parser import parse

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

from sophos_central_siem_integration import api_client
import time
from dataclasses import dataclass
import urllib.parse

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SophosCloudAPIError(Exception):
    pass


class SophosCloudState:

    def __init__(self, *args, **kwargs):
        self.state_data = {}

    def log(self, a):
        pass

    def create_state_dir(self, a):
        pass

    def load_state_file(self):
        pass

    def write_state_file(self, a):
        pass

    def get_state_file(self, a, b):
        pass

    def save_state(self, a, b):
        pass

    def load_state_file(self):
        pass


@dataclass
class Options:
    since: str
    light: bool = False
    debug: bool = False
    quiet: bool = False


@dataclass
class Config:
    filename: str
    format: str
    client_id: str
    client_secret: str
    tenant_id: str
    token_info: str
    auth_url: str
    api_host: str


class SophosCloudParser(ApiParser):
    ENDPOINT = "event"
    TOKEN_INFO = ""
    AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
    API_HOST = "api.central.sophos.com"

    DEFAULT_LAST_API_CALL_DATETIME = datetime.now(timezone.utc) - timedelta(hours=23)
    DEFAULT_LAST_API_CALL = urllib.parse.quote(str(int(round(time.mktime(DEFAULT_LAST_API_CALL_DATETIME.timetuple())))))

    def __init__(self, data):
        super().__init__(data)

        logger.info(data)
        self.client_id = data["sophos_cloud_client_id"]
        self.client_secret = data["sophos_cloud_client_secret"]
        self.tenant_id = data["sophos_cloud_tenant_id"]

        self.session = None

        api_client.ApiClient.create_log_dir = lambda this: None

    def test(self):
        if self.last_api_call:
            last_api_call = urllib.parse.quote(str(int(round(time.mktime(self.last_api_call.timetuple())))))
        else:
            last_api_call = self.DEFAULT_LAST_API_CALL

        config = Config(
            filename="stdout",
            format="json",
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
            token_info=self.TOKEN_INFO,
            auth_url=self.AUTH_URL,
            api_host=self.API_HOST
        )

        options = Options(
            since=last_api_call,
            light=False,
            debug=False,
            quiet=False
        )
        state = SophosCloudState(options, "")

        events = []
        try:
            for e in api_client.ENDPOINT_MAP[self.ENDPOINT]:
                apiclient = api_client.ApiClient(e, options, config, state)
                events.extend(iter(apiclient.get_alerts_or_events()))
            if not events:
                raise SophosCloudAPIError("There is no event returned by api")
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
        else:
            return {
                "status": True,
                "data": events
            }

    def execute(self):
        since = urllib.parse.quote(str(int(round(time.mktime(self.last_api_call.timetuple()))))) or self.DEFAULT_LAST_API_CALL
        to = datetime.now(timezone.utc)
        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        config = Config(
            filename="stdout",
            format="json",
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
            token_info=self.TOKEN_INFO,
            auth_url=self.AUTH_URL,
            api_host=self.API_HOST
        )

        options = Options(
            since=since,
            light=False,
            debug=False,
            quiet=False
        )
        state = SophosCloudState(options, "")

        events = []
        try:
            for e in api_client.ENDPOINT_MAP[self.ENDPOINT]:
                api_client.ApiClient.create_log_dir = lambda this: None
                apiclient = api_client.ApiClient(e, options, config, state)
                events.extend(iter(apiclient.get_alerts_or_events()))
            if not events:
                raise SophosCloudAPIError("There is no event returned by api")
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
        else:

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            self.write_to_file([json.dumps(e) for e in events])

            last_event_date = events[-1].get('created_at')
            if last_event_date:
                last_event_date_with_delta = parse(last_event_date) + timedelta(milliseconds=1)
                last_event_date_unix_timestamp = int(round(time.mktime(last_event_date_with_delta.timetuple())))
                last_event_date_url_encode = urllib.parse.quote(str(last_event_date_unix_timestamp))
                self.frontend.last_api_call = last_event_date_url_encode

            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
