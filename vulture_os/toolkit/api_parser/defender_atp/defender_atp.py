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
__doc__ = 'Microsoft Defender ATP API Parser'
__parser__ = 'DEFENDER ATP'

import json
import logging
import requests

from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class DefenderATPAPIError(Exception):
    pass


class DefenderATPParser(ApiParser):
    OAUTH_URL = "https://login.windows.net/{}/oauth2/token"
    API_BASE_URL = "https://api.securitycenter.windows.com"

    def __init__(self, data):
        super().__init__(data)

        self.tenant_id = data["mdatp_api_tenant"]
        self.app_id = data["mdatp_api_appid"]
        self.app_secret = data["mdatp_api_secret"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                # Retrieve OAuth token (https://docs.microsoft.com/fr-fr/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-nativeapp)
                oauth2_url = self.OAUTH_URL.format(self.tenant_id)
                response = requests.post(
                    oauth2_url,
                    data={
                        'resource' : self.API_BASE_URL,
                        'client_id' : self.app_id,
                        'client_secret' : self.app_secret,
                        'grant_type' : 'client_credentials'
                    },
                    proxies=self.proxies
                ).json()

                assert response.get('access_token') is not None, "Cannot retrieve token from API : {}".format(response)

                self.session.headers.update({'Authorization': "Bearer {}".format(response.get('access_token'))})

            return True

        except Exception as err:
            raise DefenderATPAPIError(err)

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
            logger.exception(f"{[__parser__]}:{self.test.__name__}: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since=None, test=False):
        self._connect()

        url = f"{self.API_BASE_URL}/api/alerts"

        params = {
            '$expand': "evidence"
        }
        if since:
            params['$filter'] = 'lastUpdateTime gt {}'.format(since.isoformat().replace('+00:00', "Z"))
        msg = f"Get user events request params: {params}"
        logger.debug(f"{[__parser__]}:{self.get_logs.__name__}: {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            msg = f"Error at Defender ATP API Call: {response.content}"
            logger.error(f"{[__parser__]}:{self.get_logs.__name__}: {msg}", extra={'frontend': str(self.frontend)})
            raise DefenderATPAPIError(msg)

        content = response.json()
        msg = f"Content retrieved"
        logger.info(f"{[__parser__]}:{self.get_logs.__name__}: {msg}", extra={'frontend': str(self.frontend)})
        return True, content

    def execute(self):
        status, tmp_logs = self.get_logs(since=self.last_api_call)

        if not status:
            raise DefenderATPAPIError(tmp_logs)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        logs = tmp_logs['value']

        if len(logs) > 0:
            for alert in logs:
                # Rename "evidence" field as ECS mapping
                tmp_evidence = []
                for ev in alert['evidence']:
                    tmp_evidence.append({
                        'file': {
                            'name': ev.get('fileName', "-"),
                            'path': ev.get('filePath', "-"),
                            'hash': {
                                'sha1': ev.get('sha1', "-"),
                                'sha256': ev.get('sha256', "-")
                            }
                        },
                        'process': {
                            'pid': ev.get('processId', "-"),
                            'command_line': ev.get('processCommandLine', "-"),
                            'start': ev.get('processCreationTime', "-"),
                            'parent': {
                                'pid': ev.get('parentProcessId', "-"),
                                'start': ev.get('parentProcessCreationTime', "-"),
                            }
                        },
                        'url': {
                            'full': ev.get('url', "-")
                        },
                        'source': {
                            'ip': ev.get('IpAddress', "0.0.0.1")
                        },
                        'client': {
                            'user': {
                                'name': ev.get('accountName', "-"),
                                'domain': ev.get('domainName', "-")
                            }
                        }
                    })
                alert['evidence'] = tmp_evidence

            # All alerts are retrieved, reset timezone to now
            self.frontend.last_api_call = timezone.now()

        self.write_to_file([json.dumps(l) for l in logs])
        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        logger.info(f"{[__parser__]}:{self.execute.__name__}: Parsing done.", extra={'frontend': str(self.frontend)})
