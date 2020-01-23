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


import datetime
import json
import logging
import requests

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class CybereasonParseError(Exception):
    pass


class CybereasonAPIError(Exception):
    pass


class CybereasonParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    LOGIN_URI = "login.html"
    MALOP_URI = "rest/crimes/unified"
    SENSOR_URI = "rest/sensors/query"

    def __init__(self, data):
        super().__init__(data)

        self.api_host = data['cybereason_host']
        self.username = data['cybereason_username']
        self.password = data['cybereason_password']

    def test(self):
        try:
            status, response = self.login_to_cybereason()

            if not status:
                return {
                    "status": False,
                    "error": response
                }

            return {
                'status': True,
                'data': "Success"
            }
        except CybereasonAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def login_to_cybereason(self):
        login_url = f"{self.api_host}/{self.LOGIN_URI}"

        auth = {
            "username": self.username,
            "password": self.password
        }

        session = requests.session()

        response = session.post(
            login_url,
            data=auth,
            proxies=self.proxies,
            timeout=10
        )

        if response.status_code != 200:
            error = f"Error at Cybereason API Call Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            raise CybereasonAPIError(response.content)

        if "app-login" in response.content.decode('utf-8'):
            error = f"Error at Cybereason API Call Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            return False, _('Authentication failed')

        return True, session

    def __get_affected_devices(self, tmp_devices_id):
        devices_id = []
        for tmp in tmp_devices_id:
            devices_id.append(tmp.get('guid'))

        query = {
            "limit": 10000,
            "offset": 0,
            "filters": [{
                "fieldName": "guid",
                "operator": "Equals",
                "values": devices_id
            }]
        }

        sensors_url = f"{self.api_host}/{self.SENSOR_URI}"

        response = self.session.request(
            "POST",
            sensors_url,
            json=query,
            headers=self.HEADERS,
            proxies=self.proxies
        )

        if response.status_code != 200:
            error = f"Error at Cybereason API Call URL: {self.SENSOR_URI} Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            raise CybereasonAPIError(error)

        try:
            tmp_devices = json.loads(response.content)

            devices = []
            for tmp in tmp_devices.get('sensors', []):
                devices.append({
                    "sensor_id": tmp.get('sensorId'),
                    "net_src_host": tmp.get('fqdn'),
                    "hostname": tmp.get('machineName'),
                    "net_src_ip": tmp.get('internalIpAddress'),
                    "externalIpAddress": tmp.get('externalIpAddress'),
                    "organization": tmp.get('organization'),
                    "net_src_os_name": tmp.get('osVersionType')
                })

            return devices

        except Exception as e:
            CybereasonParseError(e)

    def parse(self, malops_data):
        for malop_id, malop_info in malops_data['data']['resultIdToElementDataMap'].items():
            malop_simple_values = malop_info['simpleValues']
            malop_element_values = malop_info['elementValues']

            default_values = {
                'values': [],
                'elementValues': []
            }

            timestamp_detected = int(malop_simple_values['malopLastUpdateTime']['values'][0]) / 1000
            timestamp_detected = datetime.datetime.fromtimestamp(timestamp_detected)

            timestamp_closed = None
            if malop_simple_values['closeTime']['values'][0] is not None:
                timestamp_closed = int(malop_simple_values['closeTime']['values'][0]) / 1000
                timestamp_closed = datetime.datetime.fromtimestamp(timestamp_closed)

            affected_devices = self.__get_affected_devices(malop_element_values['affectedMachines']['elementValues'])

            tmp_malop = {
                "edr_threat_id": malop_id,
                "@timestamp": timestamp_detected,
                "timestamp_closed": timestamp_closed,
                "edr_reason": malop_simple_values['decisionFeature']['values'],
                "edr_theat_type": malop_simple_values['detectionType']['values'],
                "edr_category": malop_simple_values['malopActivityTypes']['values'],
                "edr_elements_type": malop_simple_values.get('rootCauseElementTypes', default_values)['values'],
                "edr_elements_name": malop_simple_values.get('rootCauseElementNames', default_values)['values'],
                "edr_elements_hash": malop_simple_values.get('rootCauseElementHashes', default_values)['values'],
                "edr_affected_users": malop_element_values.get('affectedUsers', default_values)['elementValues'],
                "edr_affected_devices": affected_devices,
                "edr_killchain": malop_simple_values['malopActivityTypes']['values'],
                "edr_status": malop_simple_values['managementStatus']['values'],
                "edr_is_blocked": malop_simple_values['isBlocked']['values'],
                "edr_level": malop_info['malopPriority']
            }

            yield tmp_malop

    def execute(self):
        query = {
            'totalResultLimit': 10000,
            'perGroupLimit': 10000,
            'perFeatureLimit': 100,
            'templateContext': "OVERVIEW",
            'queryPath': [{
                'requestedType': 'MalopProcess',
                'result': True,
                'filters': None
            }]
        }

        # Call login
        try:
            status, self.session = self.login_to_cybereason()
        except Exception as err:
            raise CybereasonAPIError(err)

        if not status:
            raise CybereasonAPIError(self.session)

        # We are logged in
        malop_url = f"{self.api_host}/{self.MALOP_URI}"

        response = self.session.request(
            "POST",
            malop_url,
            json=query,
            headers=self.HEADERS,
            proxies=self.proxies
        )

        if response.status_code != 200:
            error = f"Error at Cybereason API Call Code: {response.status_code} Content: {response.content}"
            logger.error(error)
            raise CybereasonAPIError(error)

        try:
            tmp_malops = json.loads(response.content)

            malops = []
            for malop in self.parse(tmp_malops):
                malops.append(malop)

        except Exception as e:
            raise CybereasonParseError(e)
