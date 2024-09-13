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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'ReachFive API Parser'
__parser__ = 'REACHFIVE'

import json
import logging
import requests

from datetime import datetime, timedelta
import time
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ReachFiveAPIError(Exception):
    pass


class ReachFiveParser(ApiParser):
    REACHFIVE_API_VERSION = 'v2'

    def __init__(self, data):
        super().__init__(data)

        self.reachfive_host = data["reachfive_host"]
        self.reachfive_client_id = data["reachfive_client_id"]
        self.reachfive_client_secret = data["reachfive_client_secret"]

        self.reachfive_access_token = data.get("reachfive_access_token")
        self.reachfive_expire_at = data.get("reachfive_expire_at")

        self.session = None

    def save_access_token(self):
        try:
            if self.frontend:
                self.frontend.reachfive_access_token = self.reachfive_access_token
                self.frontend.reachfive_expire_at = self.reachfive_expire_at
                self.frontend.save()
        except Exception as e:
            raise ReachFiveAPIError(f"Unable to save access token: {e}")

    @property
    def auth_token(self):
        if (not self.reachfive_access_token or not self.reachfive_expire_at) or (self.reachfive_expire_at - timedelta(minutes=3)) < timezone.now():
            # Retrieve OAuth token (https://developer.reachfive.com/api/management.html#tag/OAuth)
            oauth2_url = f"https://{self.reachfive_host}/oauth/token"
            response = requests.post(
                oauth2_url,
                json={
                    'grant_type': "client_credentials",
                    'client_id': self.reachfive_client_id,
                    'client_secret': self.reachfive_client_secret,
                    'scope': "read:user-events"
                },
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            ).json()

            assert (
                    response.get('access_token') is not None
            ), f"Cannot retrieve token from API : {response}"

            self.reachfive_access_token = response.get('access_token')
            self.reachfive_expire_at = timezone.now() + timedelta(seconds=response.get('expires_in'))
            self.save_access_token()
        return self.reachfive_access_token

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers = {
                        'Authorization': f"Bearer {self.auth_token}"
                }
            return True
        except Exception as err:
            raise ReachFiveAPIError(err)

    def test(self):
        try:
            status, logs = self.get_logs(count=10)

            if not status:
                return {
                    "status": False,
                    "error": logs
                }

            return {
                "status": True,
                "data": _('Success')
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})

            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, page=1, since=None, count=1000):
        self._connect()
        url = f"https://{self.reachfive_host}/api/{self.REACHFIVE_API_VERSION}/user-events"

        params = {'sort': "date:asc", 'page': page, 'count': count}

        if since:
            params['filter'] = f'date > "{since}"'

        msg = f"Get user events request params: {params}"
        logger.debug(f"[{__parser__}]:get_logs: {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            msg = f"Error at ReachFive API Call: {response.content}"
            logger.error(f"[{__parser__}]:get_logs: {msg}", extra={'frontend': str(self.frontend)})
            raise ReachFiveAPIError(msg)

        content = response.json()

        return True, content

    def execute(self):
        cpt = 0
        page = 1
        total = 1
        since = self.frontend.last_api_call.isoformat(timespec="milliseconds")

        while cpt < total and not self.evt_stop.is_set():

            status, tmp_logs = self.get_logs(page=page, since=since)

            if not status:
                raise ReachFiveAPIError(tmp_logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            total = tmp_logs['total']
            logs = tmp_logs['items']

            self.write_to_file([json.dumps(l) for l in logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            page += 1
            cpt += len(logs)

            if len(logs) > 0:

                # Get latest date returned from API (logs are often not properly ordered, even with a 'sort'ed query...)
                assert logs[0]['date'], "logs don't have a 'date' field!"
                assert logs[0]['date'][-1] == "Z", f"unexpected date format '{logs[0]['date']}', are they UTC?"
                last_datetime = [x['date'] for x in logs]
                # ISO8601 timestamps are sortable as strings
                last_datetime = max(last_datetime)
                msg = f"most recent log is from {last_datetime}"
                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                # Replace "Z" by "+00:00" for datetime parsing
                # No need to make_aware, date already contains timezone
                self.frontend.last_api_call = datetime.fromisoformat(last_datetime.replace("Z", "+00:00"))

            if cpt % 10000 == 0:
                # Sleep 10 sec every 10 000 fetched logs to avoid too many requests
                time.sleep(10)

            if page == 11:  # Get max 10 000 logs to avoid API error
                since = self.frontend.last_api_call.isoformat(timespec="milliseconds")
                page = 1
                cpt = 0

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
