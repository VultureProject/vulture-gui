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
__credits__ = ["Florian Ledoux", "Antoine Lucas"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cybereason API Parser toolkit'


from django.template import Context
from django.template import Template
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from datetime import datetime

import json
import logging
import datetime
from pprint import pformat
import requests
import time
import pprint

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CybereasonAPIError(Exception):
    pass


class CybereasonParser(ApiParser):
    LOGIN_URI = "login.html"
    MALOP_URI = "rest/crimes/unified"
    SENSOR_URI = "rest/sensors/query"
    MALWARE_URI = "rest/malware/query"
    POLICY_URI = "rest/policies"
    UPGRADE_URI = "rest/sensors/action/upgrade"
    APP_VERSION_URI = "rest/monitor/global/server/version/all"
    APP_DETAILS_URI = "rest/settings/get-detection-servers"
    APP_STATUS_URI = "rest/monitor/global/server/base/status"
    SEARCH_URI = "rest/visualsearch/query/simple"
    DESCRIPTION_URI = "rest/translate/features/all"
    DESCRIPTION_MALOP_URI = "rest/translate/malopDescriptions/all"

    MALOP_SIMPLE_VALUES = ["rootCauseElementNames", "rootCauseElementTypes", "isBlocked", "comments",
                           "malopActivityTypes", "detectionType", "malopActivityTypes", "managementStatus",
                           "elementDisplayName", "malopPriority", "rootCauseElementHashes", "decisionFeature",
                           "malopLastUpdateTime", "closeTime", "malopStartTime"]

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    DESC_TRANSLATION = {}
    DESC_MALOP_TRANSLATION = {}

    def __init__(self, data):
        super().__init__(data)

        self.host = data["cybereason_host"]
        self.username = data["cybereason_username"]
        self.password = data["cybereason_password"]
        # Remove last "/" if present
        if self.host[-1] == '/':
            self.host = self.host[:-1]
        # Remove scheme for observer
        if not "://" in self.host:
            self.observer_name = self.host
            self.host = f"https://{self.host}"
        else:
            self.observer_name = self.host.split("://")[1]


        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                login_url = f"{self.host}/{self.LOGIN_URI}"

                auth = {
                    "username": self.username,
                    "password": self.password
                }

                response = self.session.post(
                    login_url,
                    data=auth,
                    proxies=self.proxies
                )
                response.raise_for_status()
                if "app-login" in response.content.decode('utf-8'):
                    raise CybereasonAPIError(f"Authentication failed on {login_url} for user {self.username}")

                logger.info("[CYBEREASON]::_connect: Successfully logged-in", extra={'frontend': str(self.frontend)})

            return True

        except Exception as err:
            raise CybereasonAPIError(err)

    def execute_query(self, method, url, query, timeout=10):
        self._connect()

        response = None
        retry = 3
        while (retry > 0):
            retry -= 1
            try:
                response = self.session.request(method, url, json=query, proxies=self.proxies)
            except requests.exceptions.ReadTimeout:
                time.sleep(timeout)
                continue
            except requests.exceptions.ConnectionError:
                time.sleep(timeout)
                continue
            if response.status_code != 200:
                time.sleep(timeout)
                continue
            break  # no error we break from the loop

        # response.raise_for_status()
        if response == None or response.status_code != 200:
            if (response == None):
                logger.error(f"[CYBEREASON]::execute_query: Error at Cybereason API Call URL: {url} [TIMEOUT]",
                             extra={'frontend': str(self.frontend)})
            else:
                logger.error(f"[CYBEREASON]::execute_query: Error at Cybereason API Call URL: {url} Code: {response.status_code} ",
                             extra={'frontend': str(self.frontend)})
            return {}
        return json.loads(response.content)

    def getAlerts(self, since):
        malop_url = f"{self.host}/{self.MALOP_URI}"

        query = {
            "totalResultLimit": 10000,
            "perGroupLimit": 10000,
            "perFeatureLimit": 100,
            "templateContext": "OVERVIEW",
            "queryPath": [{
                "requestedType": "MalopProcess",
                "result": True,
                "filters": [{
                    'facetName': "malopLastUpdateTime",
                    'filterType': 'GreaterThan',
                    'values': [since * 1000]
                }]
            }]
        }

        tmp_malops = self.execute_query("POST", malop_url, query)
        return tmp_malops.get('data', {}).get('resultIdToElementDataMap', {})

    def getMalwares(self, since):  # since is in hour
        malware_uri = f"{self.host}/{self.MALWARE_URI}"
        query = {
            'filters': [{
                'fieldName': 'timestamp',
                'operator': 'GreaterThan',
                'values': [since * 1000]
            }],
            'limit': 1000,
            'offset': 0,
            'search': '',
            'sortDirection': 'DESC',
            'sortingFieldName': 'timestamp'
        }

        malwareList = []
        malwareToRetrieve = True
        offset = 0
        while (malwareToRetrieve):
            ret = self.execute_query("POST", malware_uri, query)
            if ('data' not in ret.keys()):
                return False, malwareList
            malwareList += ret['data']['malwares']
            if (ret['status'] != 'SUCCESS'):
                return False, malwareList
            offset += 1
            query['offset'] = offset
            if not ret['data']['hasMoreResults']:
                malwareToRetrieve = False
        return malwareList

    def parseMalwares(self, malwares):
        for i in malwares:
            i["timestamp"] = float(i['timestamp'])/1000
        return malwares

    def parseMalops(self, malops):
        # malops is a DICT which key is malop ID

        # function to get value from alert fields
        def popCybVal(sv, key):
            ret = sv.get('simpleValues', {}).get(key, {}).get('values', [])
            if (ret == None or ret == []):
                return '-'
            else:
                return ret[0]

        # Retrieve external informations for enrichment
        malopsGlobalDesc = self._descriptionsMalop()
        featureGlobalDesc = self._descriptionsFeatures()

        tmp_malops = []
        for guid, value in malops.items():
            malopDescList = []
            malopFeatureList = []
            malop_id = guid

            tmp_malop = {
                'id': guid,
                "url": f"{self.host}/#/malop/{malop_id}",
                'observer_name': f'{self.host}',
                'suspicion_list': self.suspicions(malop_id),
            }

            for field_name in self.MALOP_SIMPLE_VALUES:
                tmp_malop[field_name] = popCybVal(value, field_name)

            try:
                reason = tmp_malop['decisionFeature']
                rootEntry = reason.split('.')[0]
                subEntry = reason[len(rootEntry) + 1:].split('(')[0]
                malopDescList += [malopsGlobalDesc[rootEntry][subEntry]['single']]
                malopFeatureList += [featureGlobalDesc[rootEntry][subEntry]['translatedName']]
            except Exception as e:
                logger.error(f"[CYBEREASON]::parseMalops: Error enriching description: {e}", extra={'frontend': str(self.frontend)})

            tmp_malop['threat_rootcause'] = ' + '.join(malopDescList)
            tmp_malop['detection_type'] = ' + '.join(malopFeatureList)

            devices = []
            try:
                malopDevices = value['elementValues']['affectedMachines'].get('elementValues', [])
                devicesNames = [x['name'] for x in malopDevices]
                malopDevicesDetails = self.getDevicesDetails(devicesNames)
                for device in malopDevicesDetails:
                    devices.append({
                        "nat": {
                            "ip": device.get("internalIpAddress", '-'),
                        },
                        "hostname": device.get("machineName", '-'),
                        "os": {
                            "full": device.get("osVersionType", '-')
                        },
                        "domain": device.get("fqdn", '-'),
                        "ip": device.get("externalIpAddress", '-'),
                        "id": device.get("sensorId", '-'),
                        "type": device.get("groupName", '-'),
                        "policy": device.get("policyName", '-'),
                        "adOU": device.get("organizationalUnit", '-'),
                        "domainFqdn": device.get("organization", '-')
                    })
            except Exception as e:
                logger.error(f"[CYBEREASON]:parseMalops: Error enriching devices: {e}", extra={'frontend': str(self.frontend)})

            tmp_malop['devices'] = devices

            afUserNames = []
            try:
                if (value.get('elementValues', {}).get('affectedUsers')):
                    afUserNames = [x['name'] for x in value['elementValues']['affectedUsers']['elementValues']]
            except Exception as e:
                logger.error(f"[CYBEREASON]::parseMalops: Error parsing affected users: {e}", extra={'frontend': str(self.frontend)})

            tmp_malop['affected_users'] = afUserNames

            tmp_malop = self.parseTimestamps(tmp_malop)

            tmp_malops.append(tmp_malop)

        return tmp_malops

    def parseTimestamps(self, malop):
        try:
            timestamp_detected = float(malop['malopLastUpdateTime']) / 1000
            malop["timestamp"] = timestamp_detected
        except Exception as e:
            logger.error(f"[CYBEREASON]::parseTimestamps: Error enriching timestamp detected: {e}",
                         extra={'frontend': str(self.frontend)})
            malop["timestamp"] = float(datetime.datetime.now().timestamp())

        try:
            malop["timestamp_closed"] = float(malop['closeTime']) / 1000
        except Exception as e:
            logger.error(f"[CYBEREASON]::parseTimestamps: Error enriching timestamp closed: {e}",
                         extra={'frontend': str(self.frontend)})
            malop["timestamp_closed"] = 0.0

        try:
            malop["timestamp_start"] = float(malop['malopStartTime']) / 1000
        except Exception as e:
            logger.error(f"[CYBEREASON]::parseTimestamps: Error enriching timestamp start: {e}",
                         extra={'frontend': str(self.frontend)})
            malop["timestamp_start"] = 0.0

        return malop

    def _descriptionsMalop(self):
        if (len(self.DESC_MALOP_TRANSLATION) > 0):
            return self.DESC_MALOP_TRANSLATION

        url = f"{self.host}/{self.DESCRIPTION_MALOP_URI}"
        data = self.execute_query("GET", url, None)
        self.DESC_MALOP_TRANSLATION = data
        return data

    def _descriptionsFeatures(self):
        # retrive the traslation table for suspicion and other info from malop
        if (len(self.DESC_TRANSLATION) > 0):
            return self.DESC_TRANSLATION

        url = f"{self.host}/{self.DESCRIPTION_URI}"
        data = self.execute_query("GET", url, None)
        self.DESC_TRANSLATION = data
        return data

    def getDevicesDetails(self, devices_ids):
        sensors_url = f"{self.host}/{self.SENSOR_URI}"
        query = {
            'sortDirection': 'ASC',
            'sortingFieldName': 'machineName',
            'filters': [
                {'fieldName': "machineName", 'operator': "ContainsIgnoreCase", 'values': devices_ids},
                {"fieldName": "status", "operator": "NotEquals", "values": ["Archived"]}
            ]
        }
        data = self.execute_query("POST", sensors_url, query)
        return data.get('sensors', [])

    def suspicions(self, malop_id):
        self._descriptionsFeatures()

        status, suspicions_process = self.suspicionsProcess(malop_id)
        if not status:
            return []

        status, suspicions_network = self.suspicionsNetwork(malop_id)
        if not status:
            return []

        suspicions = [key for key in suspicions_process['data']['suspicionsMap'].keys()]
        suspicions.extend([key for key in suspicions_network['data']['suspicionsMap'].keys()])
        return suspicions

    def suspicionsProcess(self, malopId):
        # cyb.suspicions('11.-2981478659050288999')
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

        url = f"{self.host}/rest/visualsearch/query/simple"
        data = self.execute_query("POST", url, query)
        if (data['status'] != 'SUCCESS'):
            return False, data['message']
        return True, data

    def suspicionsNetwork(self, malopId):
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

        url = f"{self.host}/{self.SEARCH_URI}"
        data = self.execute_query("POST", url, query)
        if (data['status'] != 'SUCCESS'):
            return False, data['message']
        return True, data

    def test(self):
        try:
            status, observer_version = self.get_appliance_version()
            # Assert status is True, otherwize return error
            assert status, observer_version
            # Get logs from last 7 days
            query_time = (datetime.datetime.now() - datetime.timedelta(days=7)).timestamp()
            logs = self.get_logs("malops", query_time)
            logger.info(f"[CYBEREASON]::Test: {len(logs)} malops retrieved", extra={'frontend': str(self.frontend)})

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(e, extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, kind, since, test=False):
        data = []
        logger.info(f"[CYBEREASON]::get_logs: Querying '{kind}' from '{datetime.datetime.fromtimestamp(since)}'",
                    extra={'frontend': str(self.frontend)})
        try:
            if kind == "malops":
                alertes = self.getAlerts(since)
                return self.parseMalops(alertes)

            elif kind == "malwares":
                malwares = self.getMalwares(since)
                return self.parseMalwares(malwares)

            else:
                raise NotImplementedError(f"Unknown kind {kind}")

        except Exception as e:
            logger.error("[CYBEREASON]:get_logs: Error querying {} logs : ".format(kind), extra={'frontend': str(self.frontend)})
            logger.exception(e, extra={'frontend': str(self.frontend)})
            return []

    def get_appliance_version(self):
        version_url = f"{self.host}/{self.APP_VERSION_URI}"
        try:
            ret = self.execute_query("GET", version_url, {})
            return True, ret['data']['version']
        except Exception as e:
            return False, str(e)

    def execute(self):
        # Retrieve version of cybereason console
        status, observer_version = self.get_appliance_version()
        if not status:
            raise CybereasonAPIError("Failed to retrieve console version : {}".format(observer_version))

        for kind in ["malops", "malwares"]:
            # Default timestamp is 24 hours ago
            since = getattr(self.frontend, f"cybereason_{kind}_timestamp") or (timezone.now()-datetime.timedelta(days=30)).timestamp()
            tmp_logs = self.get_logs(kind, since=since)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            total = len(tmp_logs)

            if total > 0:
                logger.info(f"[CYBEREASON]::execute: {total} {kind} retrieved from "
                            f"{datetime.datetime.fromtimestamp(since)}.",
                            extra={'frontend': str(self.frontend)})
                logger.info(f"[CYBEREASON]::execute: Setting new last time for {kind} to "
                            f"{datetime.datetime.fromtimestamp(tmp_logs[0]['timestamp'])}",
                            extra={'frontend': str(self.frontend)})
                # Logs sorted by timestamp descending, so first is newer
                setattr(self.frontend, f"cybereason_{kind}_timestamp", tmp_logs[0]['timestamp'])

            def format_log(log):
                log['timestamp'] = datetime.datetime.fromtimestamp(log['timestamp']).isoformat()
                log['kind'] = kind
                log['observer_version'] = observer_version
                log['observer_name'] = self.observer_name
                return json.dumps(log)

            self.write_to_file([format_log(l) for l in tmp_logs])
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        logger.info("[CYBEREASON]::execute: Parser ending.", extra={'frontend': str(self.frontend)})
