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


KIND_TIME_FIELDS = {
    "incidents": "modification_time",
    "alerts": "event_timestamp"
}


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

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers.update({'x-xdr-auth-id': str(self.cortex_xdr_apikey_id)})
                self.session.headers.update({'Authorization': str(self.cortex_xdr_apikey)})

            return True

        except Exception as err:
            raise CortexXDRAPIError(err)

    def test(self):
        try:
            status, logs = self.get_logs("incidents", test=True)

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
            logger.exception(e, extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, kind, nb_from=0, since=None, test=False):
        self._connect()

        url = f"https://api-{self.cortex_xdr_host}/public_api/v1/{kind}/get_{kind}/"

        params = {'request_data':
                      {
                          'sort': {
                              'field': "creation_time",
                              'keyword': "asc"
                          },
                          'search_from': nb_from,
                          'search_to': nb_from+100
                      }
        }
        if test:
            params['request_data']['search_to']=10
        if since:
            params['request_data']['filters'] = [{
                       "field": "creation_time",
                       "operator": "gte",
                       "value": int(since.timestamp()*1000)
                   }]
        logger.debug("CortexXDR api::Get user events request params = {}".format(params),
                     extra={'frontend': str(self.frontend)})

        response = self.session.post(
            url,
            json=params,
            proxies=self.proxies
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            error = f"Error at CortexXDR API Call: {response.content}"
            logger.error(error, extra={'frontend': str(self.frontend)})
            raise CortexXDRAPIError(error)

        content = response.json()

        return True, content

    def execute(self):
        for kind in ["alerts", "incidents"]:
            logger.info("CortexXDR:: Getting {}".format(kind), extra={'frontend': str(self.frontend)})
            cpt = 0
            total = 1
            while cpt < total:
                status, tmp_logs = self.get_logs(kind, nb_from=cpt, since=getattr(self, f"cortex_xdr_{kind}_timestamp"))

                if not status:
                    raise CortexXDRAPIError(tmp_logs)

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                total = tmp_logs['reply']['total_count']
                cpt += tmp_logs['reply']['result_count'] + 1
                logs = tmp_logs['reply'][kind]

                def format_log(log):
                    log['kind'] = kind
                    log['timestamp'] = datetime.fromtimestamp((log[KIND_TIME_FIELDS[kind]] or log['detection_timestamp'])/1000, tz=timezone.utc).isoformat()
                    return json.dumps(log)

                self.write_to_file([format_log(l) for l in logs])
                # Writting may take some while, so refresh token in Redis
                self.update_lock()

                if len(logs) > 0:
                    # Replace "Z" by "+00:00" for datetime parsing
                    # No need to make_aware, date already contains timezone
                    # add 1 (ms) to timestamp to avoid getting last alert again
                    try:
                        setattr(self.frontend, f"cortex_xdr_{kind}_timestamp", datetime.fromtimestamp((logs[-1][KIND_TIME_FIELDS[kind]]+1)/1000, tz=timezone.utc))
                    except Exception as err:
                        logger.error(f"CortexXDR Error: Could not locate key '{KIND_TIME_FIELDS[kind]}' from following log: {logs[-1]}", extra={'frontend': str(self.frontend)})

        logger.info("CortexXDR parser ending.", extra={'frontend': str(self.frontend)})
