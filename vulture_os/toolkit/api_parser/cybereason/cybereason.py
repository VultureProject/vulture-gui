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
import datetime
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

    MAPPING = {
        "edr_reason": {
            'cybereason_key': "decisionFeature",
            'value_key': 'values'
        },
        "edr_threat_type": {
            'cybereason_key': "edr_theat_type",
            'value_key': 'values'
        },
        "edr_category": {
            'cybereason_key': "malopActivityTypes",
            'value_key': 'values'
        },
        "edr_elements_type": {
            'cybereason_key': "rootCauseElementTypes",
            'value_key': 'values'
        },
        "edr_elements_hash": {
            'cybereason_key': "rootCauseElementHashes",
            'value_key': 'values'
        },
        "edr_affected_users": {
            'cybereason_key': "affectedUsers",
            'value_key': 'elementValues'
        },
        "edr_killchain": {
            'cybereason_key': "malopActivityTypes",
            'value_key': 'values'
        },
        "edr_status": {
            'cybereason_key': "managementStatus",
            'value_key': 'values'
        },
        "edr_is_blocked": {
            'cybereason_key': "isBlocked",
            'value_key': 'values'
        },
        "edr_level": {
            'cybereason_key': "malopPriority",
            'value_key': 'values'
        }
    }

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

            for tmp in tmp_devices.get('sensors', []):
                device = {
                    "sensor_id": tmp.get('sensorId', "-"),
                    "net_src_host": tmp.get('machineName', "-"),
                    "net_src_domain": tmp.get('fqdn', "-"),
                    "net_src_ip": tmp.get('internalIpAddress', "-"),
                    "externalIpAddress": tmp.get('externalIpAddress', "-"),
                    "evt_sender_name": tmp.get('organization', "-"),
                    "net_src_os_name": tmp.get('osVersionType', "-")
                }

                yield device

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
                timestamp_closed = datetime.datetime.fromtimestamp(timestamp_closed).isoformat()

            tmp_malop = {
                "edr_threat_id": malop_id,
                "timestamp_closed": timestamp_closed,
                "@timestamp": timestamp_detected.isoformat()
            }

            rootCauseElementNames = malop_simple_values.get('rootCauseElementNames', default_values).get('values')
            tmp_malop['edr_elements_names'] = ",".join(rootCauseElementNames)

            for internal_field, cybereason_mapping in self.MAPPING.items():
                try:
                    tmp = malop_simple_values.get(cybereason_mapping['cybereason_key'], default_values)
                    tmp_malop[internal_field] = tmp.get(cybereason_mapping['value_key'])[0]
                except (IndexError, TypeError):
                    tmp_malop[internal_field] = "-"

            for device in self.__get_affected_devices(malop_element_values['affectedMachines']['elementValues']):
                tmp_malop.update(device)
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
                malops.append(json.dumps(malop))

            self.write_to_socket(malops)

        except Exception as e:
            raise CybereasonParseError(e)
