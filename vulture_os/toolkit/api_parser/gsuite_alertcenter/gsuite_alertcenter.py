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
__doc__ = 'Gsuite Alertcenter API Parser'
__parser__ = 'GSUITE ALERTCENTER'

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

from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google.auth._service_account_info import from_dict
from google.oauth2.service_account import Credentials

from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class GsuiteAlertcenterAPIError(Exception):
    pass


class GsuiteAlertcenterParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.product = 'gsuite_alertcenter'

        self.client_json_conf = data['gsuite_alertcenter_json_conf']
        self.client_admin_mail = data['gsuite_alertcenter_admin_mail']
        self.default_scopes = ['https://www.googleapis.com/auth/apps.alerts']
        self.default_client_admin_mail = "me"

        self.alertcenter = None
        self.credentials = None
        self.get_alert_center = None
        self.valid = False
        self.expiration = None
        self.first = False

    def get_creds(self):
        """
        Returns:
        """
        # use credentials
        data = json.loads(self.client_json_conf)
        signer = from_dict(data)
        self.credentials = Credentials._from_signer_and_info(signer, data, scopes=self.default_scopes)

        # impersonate with an admin email set to "me" if not provided
        if not self.client_admin_mail:
            self.client_admin_mail = self.default_client_admin_mail

        self.credentials = self.credentials.with_subject(self.client_admin_mail)

        if not self.credentials.valid:
            self.credentials.refresh(Request())
            if not self.credentials.valid:
                logger.error(f'[{__parser__}][get_creds]: Please check your configuration file and related account', exc_info=True, extra={'frontend': str(self.frontend)})
                return False, ('Connection failed')
        return self.credentials


    def get_alerts(self, since, to):

        logger.info(f"[{__parser__}]:execute: Getting alerts from {since} to {to}",
                    extra={'frontend': str(self.frontend)})

        final_filter = "createTime >= \"{}\" AND createTime < \"{}\" ".format(since, to)
        orderfilter = "create_time asc"

        self.alertcenter = build('alertcenter', 'v1beta1', credentials=self.credentials).alerts()
        recent_alerts = self.alertcenter.list(orderBy=orderfilter, filter=final_filter).execute()

        if not recent_alerts:
            return False, []
        else:
            return True, recent_alerts

    def execute(self):

        self.get_creds()
        # Default timestamp is 24 hours ago
        since = (self.last_api_call or (timezone.now() - timedelta(days=5))).isoformat()
        to = timezone.now().isoformat()
        have_logs, tmp_logs = self.get_alerts(since=since, to=to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        if have_logs:
            nb_logs = len(tmp_logs['alerts'])
            logger.info(f"[{__parser__}]execute: Total logs fetched : {nb_logs}",
                        extra={'frontend': str(self.frontend)})
            last_timestamp = datetime.fromisoformat(tmp_logs['alerts'][-1]['createTime'].replace("Z", "+00:00")) + \
                             timedelta(milliseconds=1)
            if last_timestamp > self.frontend.last_api_call:
                self.frontend.last_api_call = last_timestamp

            self.write_to_file([json.dumps(l) for l in tmp_logs['alerts']])
        else:
            logger.info(f"[{__parser__}]:execute: No recent alert found", extra={'frontend': str(self.frontend)})

        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        logger.info(f"[{__parser__}]execute: Parsing done.", extra={'frontend': str(self.frontend)})

    def test(self):
        try:
            self.get_creds()
            since = (timezone.now() - timedelta(days=10)).isoformat()
            to = timezone.now().isoformat()
            have_logs, tmp_logs = self.get_alerts(since=since, to=to)
            return {
                "status": True,
                "data": tmp_logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }