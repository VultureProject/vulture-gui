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
__credits__ = ["Jeremie Jourdin"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'NOZOMI SONDE API Parser'
__parser__ = 'NOZOMI SONDE'

import json
import logging
import requests

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser
from urllib.parse import quote_plus

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class NozomiProbeAPIError(Exception):
    pass


class NozomiProbeParser(ApiParser):
    ALERT_ENDPOINT = "api/open/query/do?query=alerts"

    def __init__(self, data):
        super().__init__(data)

        self.nozomi_probe_host = data["nozomi_probe_host"]
        self.nozomi_probe_login = data["nozomi_probe_login"]
        self.nozomi_probe_password = data["nozomi_probe_password"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.auth = (self.nozomi_probe_login, self.nozomi_probe_password)
            return True

        except Exception as err:
            raise NozomiProbeAPIError(err)

    def test(self):
        try:
            status, logs = self.get_logs(since=(timezone.now()-timedelta(days=30)))

            return {
                "status": status,
                "data": logs
            }
        except json.decoder.JSONDecodeError:
            logger.error(f"[{__parser__}]:test: API response is not a valid json",
                         extra={'frontend': str(self.frontend)})
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since=None):
        if isinstance(since, datetime):
            since = int(since.timestamp()*1000)

        self._connect()

        url = f"https://{self.nozomi_probe_host}/{self.ALERT_ENDPOINT}"
        param = "|" + quote_plus(f"where time > {since} | sort time asc")
        msg = f"Get user events request params: {param}"
        logger.debug(f"[{__parser__}]:get_logs: {msg}", extra={'frontend': str(self.frontend)})
        response = self.session.get(
            f"{url} {param}",
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            error = f"Error at NozomiProbe API Call: {response.content}"
            logger.error(f"[{__parser__}]:get_logs: {error}", extra={'frontend': str(self.frontend)})
            raise NozomiProbeAPIError(error)

        content = response.json()

        return True, content

    def execute(self):

        cpt = 0
        total = 1
        while cpt < total:
            status, tmp_logs = self.get_logs(since=self.last_api_call or timezone.now()-timedelta(days=30))

            if not status:
                raise NozomiProbeAPIError(tmp_logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            total = tmp_logs['total']
            cpt += len(tmp_logs['result'])
            logs = tmp_logs['result']

            def format_log(log):
                log['timestamp'] = datetime.fromtimestamp(log['time']/1000).isoformat()
                return json.dumps(log)

            self.write_to_file([format_log(l) for l in logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

            if len(logs) > 0:
                self.frontend.last_api_call = timezone.make_aware(datetime.fromtimestamp(logs[-1]['time']/1000))

        logger.info("NozomiProbe parser ending.", extra={'frontend': str(self.frontend)})
