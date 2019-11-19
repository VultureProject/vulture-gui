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
__doc__ = 'Cybereason API Parser'


import json
import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class CybereasonParseError(Exception):
    pass


class CybereasonAPIError(Exception):
    pass


class CybereasonParser(ApiParser):
    def __init__(self, fontend):
        super().__init__()

        self.api_host = fontend.cybereason_host
        self.username = fontend.cybereason_username
        self.password = fontend.cybereason_password

        self.login_url = "{}/{}".format(self.api_host, "login.html")
        self.malop_url = "{}/{}".format(self.api_host, 'rest/crimes/unified')

    def execute(self):
        headers = {
            "Content-Type": "application/json",
            'Accept': 'application/json'
        }

        data = {
            "username": "api_vulture@advens.fr",
            "password": "vg6K#%WsJZ##e$E4"
        }

        query = '{"totalResultLimit":10000,"perGroupLimit":10000,"perFeatureLimit":100,"templateContext":"OVERVIEW","queryPath":[{"requestedType":"MalopProcess","result":true,"filters":null}]}'

        session = requests.session()

        # Call login
        response = session.post(
            self.login_url,
            data=data
        )

        if response.status_code != 200:
            error = "Error at Cybereason API Call: {}".format(response.content)
            logger.error(error)
            raise CybereasonAPIError(error)

        # We are logged in
        response = session.request(
            "POST",
            self.malop_url,
            data=query,
            headers=headers
        )

        if response.status_code != 200:
            error = "Error at Cybereason API Call: {}".format(response.content)
            logger.error(error)
            raise CybereasonAPIError(error)

        try:
            malops = json.loads(response.content)
        except Exception as e:
            raise CybereasonParseError(e)

        print(malops)
