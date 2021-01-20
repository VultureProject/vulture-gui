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
__author__ = "Olivier De-Redis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cybereason API Parser toolkit'


import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from datetime import datetime

import json

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class CybereasonToolkit:
    LOGIN_URI = "login.html"
    MALOP_URI = "rest/crimes/unified"
    SENSOR_URI = "rest/sensors/query"
    MALWARE_URI = "rest/malware/query"
    VERSION_URI = "rest/monitor/global/server/version/all"

    PROCESSES_URI = "rest/visualsearch/query/simple"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, host, username, password, proxy):
        self.api_host = host
        self.api_username = username
        self.api_password = password
        self.proxy = proxy
        self.session = None

        if not self.api_host.startswith('https://'):
            self.api_host = f"https://{self.api_host}"

    def login_to_cybereason(self):
        login_url = f"{self.api_host}/{self.LOGIN_URI}"

        auth = {
            "username": self.api_username,
            "password": self.api_password
        }

        session = requests.session()

        response = session.post(
            login_url,
            data=auth,
            proxies=self.proxy,
            timeout=10
        )

        if response.status_code != 200:
            error = f"Error at Cybereason API Call Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            return False, _('Authentication failed')

        if "app-login" in response.content.decode('utf-8'):
            error = f"Error at Cybereason API Call Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            return False, _('Authentication failed')

        return True, session

    def execute_query(self, method, url, query=None):
        response = self.session.request(
            method,
            url,
            json=query,
            headers=self.HEADERS,
            proxies=self.proxy,
            timeout=10
        )

        if response.status_code != 200:
            error = f"Error at Cybereason API Call URL: {url} Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            raise Exception(error)

        return json.loads(response.content)

    def get_devices(self, devices, fieldName):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        query = {
            "limit": 10000,
            "offset": 0,
            "filters": [{
                "fieldName": fieldName,
                "operator": "Equals",
                "values": devices
            }]
        }

        sensors_url = f"{self.api_host}/{self.SENSOR_URI}"
        tmp_devices = self.execute_query("POST", sensors_url, query)
        return True, tmp_devices

    def get_evidence(self, malopId):
        query = {
            "queryPath": [{
                "requestedType": "MalopProcess",
                "guidList": [malopId],
                "connectionFeature": {
                    "elementInstanceType": "MalopProcess",
                    "featureName": "suspects"
                }
            }, {
                "requestedType": "Process",
                "filters": [],
                "isResult": True
            }],
            "totalResultLimit": 10000,
            "perGroupLimit": 100,
            "perFeatureLimit": 100,
            "templateContext": "SPECIFIC",
            "queryTimeout": 120000
        }

        url = f"{self.api_host}/rest/visualsearch/query/simple"
        data = self.execute_query("POST", url, query)
        return True, data

    def get_evidence_network(self, malopId):
        query = {
            "queryPath": [{
                "requestedType": "MalopProcess",
                "filters": [],
                "guidList": [malopId],
                "connectionFeature": {
                    "elementInstanceType": "MalopProcess",
                    "featureName": "suspects"
                }
            }, {
                "requestedType": "Process",
                "filters": [],
                "connectionFeature": {
                    "elementInstanceType": "Process",
                    "featureName": "connections"
                }
            }, {
                "requestedType": "Connection",
                "filters": [],
                "isResult": True
            }],
            "totalResultLimit": 1000,
            "perGroupLimit": 1200,
            "perFeatureLimit": 1200,
            "templateContext": "SPECIFIC",
            "queryTimeout": None
        }

        url = f"{self.api_host}/rest/visualsearch/query/simple"
        data = self.execute_query("POST", url, query)
        return True, data

    def get_malops(self, query):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        malop_url = f"{self.api_host}/{self.MALOP_URI}"
        tmp_malops = self.execute_query("POST", malop_url, query)
        return True, tmp_malops

    def get_malwares(self, query):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        malware_uri = f"{self.api_host}/{self.MALWARE_URI}"
        tmp_malwares = self.execute_query("POST", malware_uri, query)
        return True, tmp_malwares

    def get_version(self):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        version_uri = f"{self.api_host}/{self.VERSION_URI}"
        res = self.execute_query("GET", version_uri)
        return True, res

    def get_processes(self, query):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        processes_url = f"{self.api_host}/{self.PROCESSES_URI}"
        processes = self.execute_query("POST", processes_url, query)
        return True, processes

    def descriptions(self):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        url = f"{self.api_host}/rest/translate/malopDescriptions/all"
        tmp_descriptions = self.execute_query("GET", url, None)['Process']
        descriptions = {}

        for key, values in tmp_descriptions.items():
            descriptions[key] = values['single']

        return True, descriptions

    def translate(self):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        url = f"{self.api_host}/rest/translate/features/all"
        translate = self.execute_query("GET", url, None)
        return True, translate

    def enum(self):
        if not self.session:
            status, self.session = self.login_to_cybereason()
            if not status:
                return False, self.session

        url = f"{self.api_host}/rest/translate/enums/all"
        enum = self.execute_query("GET", url, None)
        return True, enum
