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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Forcepoint Console API Parser'


import logging
import requests
import xml.etree.ElementTree as ET

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

from django.utils.translation import ugettext_lazy as _

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class ForcepointParseError(Exception):
    pass


class ForcepointAPIError(Exception):
    pass


class ForcepointParser(ApiParser):
    FORCEPOINT_API_VERSION = '1.3.1'

    CSV_KEYS = [
        "dt_date", "dt_time", "http_uri", "af_action", "af_category", "af_direction", "af_group",
        "af_category", "af_policy", "af_risk", "af_search_term", "user_name", "net_src_workstation",
        "http_filtering_source", "http_status", "net_dst_port", "http_method", "http_tls_version",
        "http_auth_method", "af_threat_category", "net_data_center", "http_user_agent_type",
        "http_user_agent", "http_user_agent_br_type", "http_user_agent_br", "http_referer_path",
        "http_referer_port", "http_referer_query", "http_referer_url", "http_referer_full",
        "http_referer_domain", "http_referer_host", "af_threat_file", "af_threat_filetype",
        "af_threat_fullfilemimetype", "af_threat_filemimesubtype", "af_threat_filemimetype",
        "af_threat_type", "af_analytic_name", "src_ip", "net_dst_country", "src_ip", "net_src_city",
        "af_cloud_app_risk_level", "af_cloud_app", "af_could_app_category", "dst_ip", "net_name",
        "net_src_country", "af_domain", "af_subdomain", "af_topdomain", "http_host", "http_path",
        "http_request_uri", "http_query", "http_proto"
    ]

    def __init__(self, data):
        super().__init__(data)

        self.forcepoint_host = data["forcepoint_host"]
        self.forcepoint_username = data["forcepoint_username"]
        self.forcepoint_password = data["forcepoint_password"]

        self.user_agent = {
            'User-agent': f'FTL_Download/{self.FORCEPOINT_API_VERSION}'
        }

    def test(self):
        try:
            status, logs = self.get_logs()

            if not status:
                return {
                    "status": False,
                    "error": logs
                }

            return {
                "status": True,
                "data": _('Success')
            }
        except ForcepointAPIError as e:
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, url=None, allow_redirects=False):
        if url is None:
            url = f"{self.forcepoint_host}/hosted/logs"

        response = requests.get(
            url,
            auth=(self.forcepoint_username, self.forcepoint_password),
            headers=self.user_agent,
            proxies=self.get_system_proxy(),
            allow_redirects=allow_redirects
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            error = f"Error at Forcepoint API Call: {response.content}"
            logger.error(error)
            raise ForcepointAPIError(error)

        content = response.content

        return True, content

    def parse_xml(self, logs):
        root = ET.fromstring(logs)
        for child in root:
            # child.tag is 'log'
            # child.attrib is {'time': '2018-08-21 12:45', 'version': '100', 'size': '0', 'url': 'https://hlfs-web-a.mailcontrol.com/logs/hosted_S01B_29937_85.115.56.190_100_1534855500_1.gz'}

            time_log = child.attrib['time']
            url = child.attrib['url']
            status, data = self.get_logs(url=url, allow_redirects=True)
            if not status:
                raise ForcepointAPIError(data)

            for line in data.decode('utf-8').split('\r\n')[1:]:
                print(line)
                print('')
            break

    def execute(self):
        status, tmp_logs = self.get_logs()

        if not status:
            raise ForcepointAPIError(tmp_logs)

        logs = self.parse_xml(tmp_logs)
