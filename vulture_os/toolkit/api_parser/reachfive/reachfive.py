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


import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from datetime import datetime

import json

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

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
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
                    proxies=self.proxies
                ).json()

                assert response.get('access_token') is not None, "Cannot retrieve token from API : {}".format(response)

                self.session.headers.update({'Authorization': "Bearer {}".format(response.get('access_token'))})

            return True

        except Exception as err:
            raise ReachFiveAPIError(err)

    def test(self):
        try:
            status, logs = self.get_logs(test=True)

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
            logger.exception(e, extra={'frontend': self.frontend.name})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, page=1, since=None, test=False):
        self._connect()

        url = f"https://{self.reachfive_host}/api/{self.REACHFIVE_API_VERSION}/user-events"

        params = {'sort':"date:asc", 'page': page}
        if not test:
            params['count']=1000
        if since:
            params['filter'] = 'date > "{}"'.format(timezone.make_naive(since).isoformat(timespec="milliseconds"))
        logger.debug("ReachFive api::Get user events request params = {}".format(params),
                     extra={'frontend': self.frontend.name})

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            error = f"Error at ReachFive API Call: {response.content}"
            logger.error(error, extra={'frontend': self.frontend.name})
            raise ReachFiveAPIError(error)

        content = response.json()

        return True, content

    def execute(self):
        cpt = 0
        page = 1
        total = 1
        last_datetime = self.frontend.last_api_call.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        while cpt < total:
            status, tmp_logs = self.get_logs(page=page, since=self.last_api_call)

            if not status:
                raise ReachFiveAPIError(tmp_logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            total = tmp_logs['total']
            logs = tmp_logs['items']

            self.write_to_file([json.dumps(l) for l in tmp_logs['items']])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            page += 1
            cpt += len(logs)

            if len(logs) > 0:
                # Get latest date returned from API (logs are often not properly ordered, even with a 'sort'ed query...)
                assert logs[0]['date'], "logs don't have a 'date' field!"
                assert logs[0]['date'][-1] == "Z", f"unexpected date format '{logs[0]['date']}', are they UTC?"
                last_datetime = [last_datetime]
                last_datetime.extend([x['date'] for x in logs])
                # ISO8601 timestamps are sortable as strings
                last_datetime = max(last_datetime)
                logger.debug(f"most recent log is from {last_datetime}",
                             extra={'frontend': self.frontend.name})

        # Replace "Z" by "+00:00" for datetime parsing
        # No need to make_aware, date already contains timezone
        self.frontend.last_api_call = datetime.fromisoformat(last_datetime.replace("Z", "+00:00"))

        logger.info("ReachFive parser ending.", extra={'frontend': self.frontend.name})
