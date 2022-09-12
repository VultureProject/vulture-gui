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
from django.utils.translation import ugettext_lazy as _
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
                self.session.headers['Cookie'] = "f4KtYUth=534b64e7832e54c3b142a8800946c207d6de1bd4c80c6e2588338837f75bb23d; SRVNAME=advensfr3; csrftk=32daKb2mp1L0jCU2OXEwa6QRabKR8K5R; ev5yh6Hn=kkKZm8R1z9fK315uyabVBPO2PthqNUoSsdtlGpf0dLMU65PWwFLu4M0KKOIrCzf4; _n2os-webconsole_session-97be1908c2970a9b31d03e0d2bd37758f726890cb6d794629d7cb3398e3e5ff9=b90863cc76775e03e9f90bb6de0bd789; XSRF-TOKEN-a0d5c94c-51dc-4417-93ff-af4ac4a6f5a7=4%2BaDzUvHU5KzBOYHTjI7qztISmrFiTu89OudTeloAF36KjkpX4zIFq32%2FJ52ruwOpJ16WTURgkIUUBbbBmbqfA%3D%3D; NG_TRANSLATE_LANG_KEY=en"
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
            since = since.timestamp()*1000

        self._connect()

        url = f"https://{self.nozomi_probe_host}/{self.ALERT_ENDPOINT}"
        param = "|" + quote_plus(f"where time > {since} | sort time asc")
        msg = f"Get user events request params: {param}"
        logger.debug(f"[{__parser__}]:get_logs: {msg}", extra={'frontend': str(self.frontend)})
        response = self.session.get(
            f"{url} {param}",
            proxies=self.proxies
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
