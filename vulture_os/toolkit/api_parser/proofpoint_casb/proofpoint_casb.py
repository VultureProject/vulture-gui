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
__author__ = "William DARKWA"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Proofpoint CASB API Parser'
__parser__ = 'PROOFPOINT CASB'


from datetime import datetime, timedelta
import json
import logging

import requests

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class ProofPointCASBAPIError(Exception):
    pass

class ProofpointCASBParser(ApiParser):

    HOST_URL = "https://api.protect.proofpoint.com"
    OAUTH_URL = "/v1/auth"
    ALERTS_URL= "/v1/alerts"
    HEADERS = {
        "Content-Type": "application/json",
    }

    def __init__(self, data):
        super().__init__(data)

        self.proofpoint_casb_api_key = data.get('proofpoint_casb_api_key')
        self.proofpoint_casb_client_id = data.get('proofpoint_casb_client_id')
        self.proofpoint_casb_client_secret = data.get('proofpoint_casb_client_secret')
        self.session = None


    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers.update(self.HEADERS)
                self.session.headers.update({'x-api-key': self.proofpoint_casb_api_key})

            response = self.session.post(
                f"{self.HOST_URL}{self.OAUTH_URL}",
                json={
                    'client_id' : self.proofpoint_casb_client_id,
                    'client_secret' : self.proofpoint_casb_client_secret
                },
                proxies=self.proxies
            ).json()
            assert response.get('auth_token') is not None, "Cannot retrieve token from API : {}".format(response)

            self.session.headers.update({'Authorization': response.get('auth_token')})

            return True

        except Exception as err:
            raise ProofPointCASBAPIError(err)


    def get_logs(self, since, to=timezone.now(), page = 0):
        if self.session is None:
            self._connect()

        if isinstance(since, datetime):
            since = int(since.timestamp() * 1000)
        if isinstance(to, datetime):
            to = int(to.timestamp() * 1000)

        res = self.session.post(
            f"{self.HOST_URL}{self.ALERTS_URL}",
            json={
                "page": page,
                "time_range":{
                    "from": since,
                    "to": to
                }
            },
            proxies=self.proxies
        )
        res.raise_for_status()
        return res.json()


    def test(self):
        since = timezone.now() - timedelta(hours=2)
        msg = None
        logger.debug(f"[{__parser__}]:test: Testing parse starting of logs from {since} to {timezone.now()}", extra={'frontend': str(self.frontend)})
        try:
            msg = self.get_logs(since=since)
        except Exception as e:
            return {
                'status': False,
                 'error': f'Error while fetching sample message from API: {e}'
            }

        return {
            'status': True,
            'data': msg
        }


    def execute(self):
        # Retrieve last_api_call, make timezone naive
        since = self.last_api_call if self.last_api_call else (timezone.now() - timedelta(hours=24))

        # fetch at most 24h of logs to avoid the process running for too long
        to = min(timezone.now(), since + timedelta(hours=24))

        # Download logs starting from last_api_call
        logger.info(f"[{__parser__}]:execute: Parser starting from {since} to {to}", extra={'frontend': str(self.frontend)})

        first = True
        nb_logs = 0
        page = -1
        while(nb_logs == 50 or first):
            page += 1
            try:
                response = self.get_logs(since, to, page=page)

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                # Get logs from API response
                logs = response['alerts']
                nb_logs = len(logs)

                # Send logs to Rsyslog
                self.write_to_file([json.dumps(l) for l in logs])

                # Writing may take some while, so refresh token in Redis
                self.update_lock()

                if first:
                    # Events are sorted in descending order by event timestamp (epoch milliseconds) and page 0 contains the most recent logs
                    # so store last log time in DB
                    self.frontend.last_api_call = timezone.make_aware(datetime.fromtimestamp(logs[0]['timestamp']/1000)) if nb_logs > 0 else self.frontend.last_api_call
                    first = False

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.warning(f"[{__parser__}]:parse_log: could not parse a log line -> {e}", extra={'frontend': str(self.frontend)})
                logger.debug(f"[{__parser__}]:parse_log: log is {response}", extra={'frontend': str(self.frontend)})
                return None

            except Exception as err:
                raise ProofPointCASBAPIError(err)

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})