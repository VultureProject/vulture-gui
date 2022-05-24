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
__author__ = "alucas"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Google GSUITE API Parser'
__parser__ = 'GOOGLE GSUITE'

import json
import jwt
import logging
import requests
import time
import uuid

from datetime import timedelta
from datetime import datetime
from django.conf import settings
from django.utils import dateparse
from django.utils import timezone

from google.oauth2 import service_account
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class GsuiteAPIError(Exception):
    pass


class GsuiteParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.product = 'google_alertcenter'

        self.client_json_conf = data['google_client_json_conf']
        self.client_admin_mail = data['google_client_admin_mail']
        self.scopes = data['google_client_scopes']
        self.default_scopes = ['https://www.googleapis.com/auth/apps.alerts']
        self.default_client_admin_mail = "me"

        self.alertcenter = None
        self.credentials = None
        self.get_alert_center = None
        self.valid = False
        self.expiration = None
        self.get_creds()

    def get_creds(self):
        """
        Returns:
        """
        logger.info(f"[{__parser__}][get_creds]: Asking google to check credentials", extra={'frontend': str(self.frontend)})

        if self.scopes:
            # add defaults
            logger.info(f"[{__parser__}][get_creds]: Adding scopes {self.scopes} to defaults", extra={'frontend': str(self.frontend)})
            self.scopes += self.default_scopes

        # use credentials
        self.credentials = service_account.Credentials.from_service_account_file(json.loads(self.client_json_conf), scopes=self.scopes)

        # impersonate with an admin email set to "me" if not provided
        if not self.client_admin_mail:
            self.client_admin_mail = self.default_client_admin_mail

        logger.info(f"[{__parser__}][get_creds]: Admin mail: {self.client_admin_mail}", extra={'frontend': str(self.frontend)})
        self.credentials = self.credentials.with_subject(self.client_admin_mail)
        self.credentials.refresh(Request())

        logger.info(f"[{__parser__}][get_creds]: Token valid: {self.credentials.valid}, Token expiration: {self.credentials.expiry}", extra={'frontend': str(self.frontend)})
        if not self.credentials.valid:
            logger.error(f'[{__parser__}][get_creds]: Please check your configuration file and related account', exc_info=True, extra={'frontend': str(self.frontend)})
            return False, ('Connection failed')

        return True, self.credentials

    def get_alertcenter(self):
        logger.info(f"[{__parser__}][get_alertcenter]: Get the alertcli center", extra={'frontend': str(self.frontend)})
        try:
            self.alertcenter = build('alertcenter', 'v1beta1', credentials=self.credentials).alerts()
        except Exception as e:
            logger.error(f"[{__parser__}][get_alertcenter]: Failed to get the altercenter client, should investigate this: {e}", exc_info=True, extra={'frontend': str(self.frontend)})
            self.alertcenter = None
            return False, self.alertcenter
        return True, self.alertcenter

    def get_alerts(self, since, to):
        logger.debug(f"[{__parser__}][get_alerts]: From {since} until {to}",  extra={'frontend': str(self.frontend)})
        one_min_behind = datetime.utcnow() - timedelta(minutes=1)
        now = datetime.utcnow()
        time_filter_str1 = one_min_behind.isoformat().split(".")[0] + "Z"
        time_filter_str2 = now.isoformat().split(".")[0] + "Z"
        final_filter = "createTime >= \"{}\" AND createTime < \"{}\" ".format(time_filter_str1, time_filter_str2)
        orderfilter = "create_time desc"
        logger.info(f"[{__parser__}][get_alerts]: Filter {final_filter}",  extra={'frontend': str(self.frontend)})
        recent_alerts = self.alertcenter.list(orderBy=orderfilter, filter=final_filter).execute()
        if not recent_alerts:
            logger.info(f"[{__parser__}][get_alerts]: no new alerts received", extra={'frontend': str(self.frontend)})
            return False, []
        else:
            num_alerts = len(recent_alerts['alerts'])
            logger.info(f"[{__parser__}][get_alerts]: {num_alerts} founds!", extra={'frontend': str(self.frontend)})
            return True, recent_alerts

    def execute(self):
        # Default timestamp is 24 hours ago
        since = (self.last_api_call or (timezone.now() - timedelta(days=7))).strftime("%Y-%m-%dT%H:%M:%SZ")
        to = timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        have_logs, tmp_logs = self.get_alerts(since=since, to=to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        if have_logs:
            nb_logs = len(tmp_logs)
            logger.info(f"[{__parser__}][execute]: Total logs fetched : {nb_logs}",  extra={'frontend': str(self.frontend)})
            last_timestamp = datetime.fromisoformat(tmp_logs[-1]['createTime'].replace("Z", "+00:00")) + timedelta(milliseconds=10)
            if last_timestamp > self.frontend.last_api_call:
                self.frontend.last_api_call = last_timestamp

        self.write_to_file([json.dumps(l) for l in tmp_logs])

        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        logger.info(f"[{__parser__}][execute]: Parsing done.", extra={'frontend': str(self.frontend)})