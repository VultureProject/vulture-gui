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
__doc__ = 'Cortex XDR API Parser'
__parser__ = 'CORTEX XDR'

import hashlib
import json
import logging
import secrets
import string

import requests

from datetime import datetime, timedelta
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CortexXDRAPIError(Exception):
    pass


class CortexXDRParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.cortex_xdr_host = data["cortex_xdr_host"]
        self.cortex_xdr_apikey_id = data["cortex_xdr_apikey_id"]
        self.cortex_xdr_apikey = data["cortex_xdr_apikey"]
        self.cortex_xdr_alerts_timestamp = data.get("cortex_xdr_alerts_timestamp")
        self.cortex_xdr_incidents_timestamp = data.get("cortex_xdr_incidents_timestamp")
        self.cortex_xdr_advanced_token = data.get("cortex_xdr_advanced_token", False)

        # Remove potential scheme from URL
        self.cortex_xdr_host = self.cortex_xdr_host.split("://")[-1]
        # Strip '/' from beginning and end of host
        self.cortex_xdr_host = self.cortex_xdr_host.strip("/")
        # Remove potential 'api-' prefix from hostname, will be added automatically (removeprefix is python3.9+)
        self.cortex_xdr_host = self.cortex_xdr_host.removeprefix("api-")

        self.session = None

        self.event_kinds = {
            "alerts": {
                "url": f"https://api-{self.cortex_xdr_host}/public_api/v2/alerts/get_alerts_multi_events/",
                "time_field": "local_insert_ts",
                "default_time_field": "detection_timestamp",
                "filter_by": "server_creation_time"
            },
            "incidents": {
                "url": f"https://api-{self.cortex_xdr_host}/public_api/v1/incidents/get_incidents/",
                "time_field": "modification_time",
                "default_time_field": "detection_timestamp",
                "filter_by": "creation_time"
            }
        }

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                logger.debug(f"[{__parser__}]:connect: Initialising session...", extra={'frontend': str(self.frontend)})

                if self.cortex_xdr_advanced_token:
                    nonce = ''.join(
                        [secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
                    timestamp = int(timezone.now().timestamp()) * 1000

                    auth_key = f"{self.cortex_xdr_apikey}{nonce}{timestamp}".encode('utf-8')
                    auth_key = hashlib.sha256(auth_key).hexdigest()

                    self.session.headers.update({'Authorization': str(auth_key)})
                    self.session.headers.update({'x-xdr-auth-id': str(self.cortex_xdr_apikey_id)})
                    self.session.headers.update({'x-xdr-timestamp': str(timestamp)})
                    self.session.headers.update({'x-xdr-nonce': str(nonce)})
                else:
                    self.session.headers.update({'x-xdr-auth-id': str(self.cortex_xdr_apikey_id)})
                    self.session.headers.update({'Authorization': str(self.cortex_xdr_apikey)})
            return True

        except Exception as err:
            raise CortexXDRAPIError(err)

    def test(self):
        try:
            logs = self.get_logs("incidents", test=True)

            if not logs:
                return {
                    "status": False,
                    "error": _("Could not get any logs")
                }

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

    def get_logs(self, kind, nb_from=0, since=None, to=None, test=False):
        self._connect()

        url = self.event_kinds[kind]['url']

        params = {'request_data':
                      {
                          'sort': {
                              'field': self.event_kinds[kind]['filter_by'],
                              'keyword': "asc"
                          },
                          'search_from': nb_from,
                          'search_to': 10 if test else nb_from+100,
                          'filters': []
                      }
        }
        if since:
            params['request_data']['filters'].append({
                       "field": self.event_kinds[kind]['filter_by'],
                       "operator": "gte",
                       "value": int(since.timestamp()*1000)
                   })
        if to:
            params['request_data']['filters'].append({
                "field": self.event_kinds[kind]['filter_by'],
                "operator": "lte",
                "value": int(to.timestamp() * 1000)
            })

        response = None
        retry = 1
        while retry <= 3 and not self.evt_stop.is_set():
            logger.info(f"[{__parser__}]:execute_query: URL: {url}, parameters: {params}, (try {retry})", extra={'frontend': str(self.frontend)})
            response = self.session.post(
                url,
                json=params,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            )

            if response.status_code == 401:
                logger.warning(f"[{__parser__}]:get_logs: Could not authenticate: {response.content}", extra={'frontend': str(self.frontend)})
                logger.warning(f"[{__parser__}]:get_logs: Session has been reset", extra={'frontend': str(self.frontend)})
                self.session = None
                retry += 1
                continue
            else:
                break

        if response is not None:
            if response.status_code == 401:
                raise CortexXDRAPIError( _('Authentication failed'))

            if response.status_code != 200:
                error = f"Error at CortexXDR API Call: {response.content}"
                logger.error(f"[{__parser__}]:get_logs: {error}", extra={'frontend': str(self.frontend)})
                raise CortexXDRAPIError(error)

            return response.json()
        else:
            return None

    def format_log(self, log, kind):
        log['kind'] = kind

        log_timestamp = log.get(self.event_kinds[kind]['time_field'], log.get(self.event_kinds[kind]['default_time_field']))
        if isinstance(log_timestamp, list) and len(log_timestamp) > 0:
            log_timestamp = log_timestamp[0]

        log['timestamp'] = datetime.fromtimestamp(log_timestamp/1000, tz=timezone.utc).isoformat()

        return json.dumps(log)


    def execute(self):
        for kind in self.event_kinds.keys():
            logger.info(f"[{__parser__}]:execute: Getting {kind}", extra={'frontend': str(self.frontend)})
            # Prevent requesting too newer alerts, sometimes case_id is empty and added later
            # Delay of 2 minutes seems acceptable
            since = getattr(self, f"cortex_xdr_{kind}_timestamp") or timezone.now()-timedelta(hours=1)
            # Query maximum 24 hours at a time to prevent too large periods
            to = min(timezone.now()-timedelta(minutes=2), since+timedelta(hours=24))
            if since > to:
                logger.info(f"[{__parser__}]:execute: Last timestamp too recent, waiting next execution.",
                            extra={'frontend': str(self.frontend)})
                continue

            cpt = 0
            total = 1
            while cpt < total and not self.evt_stop.is_set():
                reply_obj = self.get_logs(kind, nb_from=cpt, since=since, to=to)

                if reply_obj:
                    reply = reply_obj.get('reply', {})

                    # Downloading may take some while, so refresh token in Redis
                    self.update_lock()

                    total = int(reply['total_count'])
                    cpt += int(reply['result_count'])
                    logs = reply[kind]

                    self.write_to_file([self.format_log(log, kind) for log in logs])
                    # Writting may take some while, so refresh token in Redis
                    self.update_lock()

                    if len(logs) > 0:
                        # Replace "Z" by "+00:00" for datetime parsing
                        # No need to make_aware, date already contains timezone
                        # add 1 (ms) to timestamp to avoid getting last alert again
                        try:
                            updated_datetime = datetime.fromtimestamp((logs[-1][self.event_kinds[kind]['time_field']]+1)/1000, tz=timezone.utc)
                            setattr(self.frontend, f"cortex_xdr_{kind}_timestamp", updated_datetime)
                            self.frontend.save(update_fields=[f"cortex_xdr_{kind}_timestamp"])
                            logger.info(f"[{__parser__}]:execute: Updated cortex_xdr_{kind}_timestamp to {updated_datetime}",
                                    extra={'frontend': str(self.frontend)})
                        except Exception:
                            msg = f"Could not locate key '{self.event_kinds[kind]['time_field']}' from following log: {logs[-1]}"
                            logger.error(f"[{__parser__}]:execute: {msg}",
                                         extra={'frontend': str(self.frontend)})
                    elif to - since >= timedelta(hours=24):
                        updated_datetime = since + timedelta(hours=1)
                        setattr(self.frontend, f"cortex_xdr_{kind}_timestamp", updated_datetime)
                        self.frontend.save(update_fields=[f"cortex_xdr_{kind}_timestamp"])
                        logger.info(f"[{__parser__}]:execute: Updated cortex_xdr_{kind}_timestamp to {updated_datetime}",
                                extra={'frontend': str(self.frontend)})

        logger.info("CortexXDR parser ending.", extra={'frontend': str(self.frontend)})
