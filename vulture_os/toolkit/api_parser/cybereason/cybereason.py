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
__credits__ = ["Olivier De-Regis"]
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
from toolkit.api_parser.cybereason.cybereason_toolkit import CybereasonToolkit

import json
import logging
import datetime
from pprint import pformat

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class CybereasonAPIError(Exception):
    pass


class CybereasonParser(ApiParser):
    MAPPING_MALOPS = {
        "reason": {
            'cybereason_key': "decisionFeature",
            'value_key': 'values'
        },
        "threat_type": {
            'cybereason_key': "detectionType",
            'value_key': 'values'
        },
        # "edr_threat_rootcause": {
        #     'cybereason_key': "rootCauseElementCompanyProduct",
        #     "value_key": "values"
        # },
        "category": {
            'cybereason_key': "malopActivityTypes",
            'value_key': 'values'
        },
        "elements_type": {
            'cybereason_key': "rootCauseElementTypes",
            'value_key': 'values'
        },
        "killchain": {
            'cybereason_key': "malopActivityTypes",
            'value_key': 'values'
        },
        "status": {
            'cybereason_key': "managementStatus",
            'value_key': 'values'
        },
        "is_blocked": {
            'cybereason_key': "isBlocked",
            'value_key': 'values'
        },
        "level": {
            'cybereason_key': "malopPriority",
            'value_key': 'values'
        },
        "timestamp_start": {
            'cybereason_key': "malopStartTime",
            'value_key': 'values'
        },
        "af_reason": {
            'cybereason_key': "elementDisplayName",
            'value_key': 'values'
        },
    }

    def __init__(self, data):
        super().__init__(data)

        self.host = data["cybereason_host"]
        self.username = data["cybereason_username"]
        self.password = data["cybereason_password"]
        if not "://" in self.host:
            self.observer_name = self.host
            self.host = f"https://{self.host}"
        else:
            self.observer_name = self.host.split("://")[1]
        self.cyber_tool = CybereasonToolkit(self.host, self.username, self.password, self.proxies)

    def execute_query(self, kind, since, test=False, requestedType=None):
        if kind == "malops":
            self.query = {
                'totalResultLimit': 10000,
                'perGroupLimit': 10000,
                'perFeatureLimit': 100,
                'templateContext': 'OVERVIEW',
                'queryPath': []
            }

            queryPath = {
                'requestedType': requestedType,
                'result': True,
                'filters': [{
                    'facetName': "malopLastUpdateTime",
                    'filterType': 'GreaterThan',
                    'values': [
                        since * 1000
                    ]
                }]
            }

            self.query['queryPath'].append(queryPath)

        elif kind == "malwares":
            self.query = {
                "filters": [{
                    "fieldName": "timestamp",
                    "operator": "GreaterThan",
                    "values": [since * 1000]
                }],
                "sortingFieldName": "timestamp",
                "sortDirection": "DESC",
                "limit": 1000,
                "offset": 0,
                "search": ""
            }

        logger.info(f"[CYBEREASON PLUGIN] Executing {json.dumps(self.query)}")

    def __get_affected_devices(self, devices, fieldName, test=False):
        status, tmp_devices = self.cyber_tool.get_devices(devices, fieldName)
        if not status:
            raise Exception(tmp_devices)

        for tmp in tmp_devices.get('sensors', []):
            tmp_fqdn = tmp.get('fqdn', "-").split('.')

            if len(tmp_fqdn) > 1:
                fqdn = f'{tmp_fqdn[-2]}.{tmp_fqdn[-1]}'
            elif len(tmp_fqdn) == 1:
                fqdn = tmp_fqdn[0]
            else:
                fqdn = "-"

            device = {
                'host': {
                    'domain': fqdn,
                    "id": tmp.get('sensorId', "-"),
                    "hostname": tmp.get('machineName', "-"),
                    "ip": tmp.get('internalIpAddress', "0.0.0.1"),
                    "type": tmp.get('organization', "-"),
                    "nat": {
                        'ip': tmp.get('externalIpAddress', "0.0.0.1"),
                    },
                    'os': {
                        'full': tmp.get('osVersionType', "-")
                    }
                }
            }

            yield device

            if test:
                break

    def __get_affected_machines(self, devices, test=False):
        status, tmp_devices = self.cyber_tool.get_machines(devices)
        if not status:
            raise Exception(tmp_devices)
        devices = []
        for device_k,device_v in tmp_devices['data']['resultIdToElementDataMap'].items():
            devices.append({key:value['values'][0] for key, value in device_v['simpleValues'].items()})
            if test:
                break
        return devices

    def __get_evidence(self, malop_id):
        status, evidences = self.cyber_tool.get_evidence(malop_id)
        if not status:
            raise Exception(evidences)

        evidences = [key for key in evidences['data']['suspicionsMap'].keys()]
        status, evidences_network = self.cyber_tool.get_evidence_network(malop_id)

        if not status:
            raise Exception(evidences)

        evidences.extend([key for key in evidences_network['data']['suspicionsMap'].keys()])
        return evidences

    def parse_malops(self, malops_data, test):
        status, descriptions = self.cyber_tool.descriptions()
        status, translate_process = self.cyber_tool.translate()
        # status, enums = self.cyber_tool.enum()

        for malop_id, malop_info in malops_data['data']['resultIdToElementDataMap'].items():
            malop_simple_values = malop_info['simpleValues']
            malop_element_values = malop_info['elementValues']

            default_values = {
                'values': [],
                'elementValues': []
            }

            timestamp_detected = float(malop_simple_values['malopLastUpdateTime']['values'][0]) / 1000

            timestamp_closed = 0.0
            if malop_simple_values['closeTime']['values'][0] is not None:
                timestamp_closed = float(malop_simple_values['closeTime']['values'][0]) / 1000
            timestamp_start = 0.0
            if malop_simple_values['malopStartTime']['values'][0] is not None:
                timestamp_start = float(malop_simple_values['malopStartTime']['values'][0]) / 1000

            tmp_malop = {
                "threat_url": self.host + "#/malop/" + malop_id,
                "threat_id": malop_id,
                "timestamp_start": timestamp_start,
                "timestamp_closed": timestamp_closed,
                "timestamp": timestamp_detected,
                'affected_devices': []
            }

            tmp_malop['elements_names'] = malop_simple_values.get(
                'rootCauseElementNames', default_values
            ).get('values')

            tmp_malop['elements_hash'] = malop_simple_values.get(
                'rootCauseElementHashes', default_values
            ).get('values')

            tmp_malop['killchain'] = malop_simple_values.get(
                'malopActivityTypes', default_values
            ).get('values')

            tmp_malop['comments'] = malop_simple_values.get(
                'comments', default_values
            ).get('values')


            for internal_field, cybereason_mapping in self.MAPPING_MALOPS.items():
                try:
                    tmp = malop_simple_values.get(cybereason_mapping['cybereason_key'], default_values)
                    tmp_malop[internal_field] = tmp.get(cybereason_mapping['value_key'])[0]
                except (IndexError, TypeError):
                    tmp_malop[internal_field] = "-"

                if internal_field == "reason":
                    val = tmp_malop[internal_field].replace('Process.', '').replace('(Malop decision)', '')
                    descr = descriptions.get(val)

                    if descr:
                        tmp = ", ".join(tmp_malop['elements_names'])
                        tmp_malop['threat_rootcause'] = Template(descr).render(Context({
                            "suspectName": tmp
                        }))

            feature_name, tmp = tmp_malop['reason'].split('.')
            tmp = tmp.split('(')[0]

            try:
                edr_detection_type = translate_process[feature_name][tmp]['translatedName']
            except KeyError:
                edr_detection_type = None

            tmp_malop['detection_type'] = edr_detection_type

            devices = []
            for tmp in malop_element_values['affectedMachines']['elementValues']:
                devices.append(tmp.get("guid"))

            users = []
            if malop_element_values.get('affectedUsers'):
                for tmp in malop_element_values['affectedUsers']['elementValues']:
                    users.append(tmp.get("name"))
            tmp_malop['affected_users'] = users

            edr_suspicions_list = self.__get_evidence(malop_id)
            # edr_suspicions_list = []
            # for suspicion in tmp_edr_suspicions_list:
            # try:
            #     edr_suspicions_list.append(translate_process[tmp_malop['edr_elements_type']][suspicion]['translatedName'])
            # except KeyError:
            #     edr_suspicions_list.append(suspicion)

            # guid_root_cause_list = {}
            # for tmp in malop_element_values['primaryRootCauseElements']['elementValues']:
            #     try:
            #         guid_root_cause_list[tmp['elementType']].append(tmp['guid'])
            #     except KeyError:
            #         guid_root_cause_list[tmp['elementType']] = [tmp['guid']]

            # root_cause = []
            # edr_suspicions_list = []
            # for elem_type, guid_list in guid_root_cause_list.items():
            #     root_cause = self.__get_evidence(elem_type, list(set(guid_list)))
            #     names = [key for key in root_cause['data']['suspicionsMap'].keys()]

            #     for name in names:
            #         try:
            #             # description_process = translate_process[elem_type][name]['description']
            #             edr_suspicions_list.append(translate_process[elem_type][name]['translatedName'])
            #         except KeyError:
            #             pass

            tmp_malop['suspicions_list'] = edr_suspicions_list
            tmp_affected_machines = self.__get_affected_devices(
                devices,
                'guid',
                test
            )

            for device in tmp_affected_machines:
                tmp_malop['affected_devices'].append(device)
                if test:
                    break

            tmp_malop['affected_machines'] = self.__get_affected_machines(devices, test)

            yield tmp_malop

    def parse_malwares(self, malwares_data, test):
        malwares = {}
        tmp_machines = {}

        for tmp_malware in malwares_data:
            timestamp = float(tmp_malware['timestamp']) / 1000

            malware_guid = tmp_malware['guid']

            try:
                tmp_machines[malware_guid].append(tmp_malware['machineName'])
            except KeyError:
                tmp_machines[malware_guid] = [tmp_malware['machineName']]

            malwares[malware_guid] = {
                "timestamp": timestamp,
                'affected_devices': [],
                "threat_id": tmp_malware['guid'],
                "name": tmp_malware['name'],
                "category": tmp_malware['type'],
                "threat_type": tmp_malware['elementType'],
                "status": tmp_malware['status'],
                "machine_name": tmp_malware['machineName'],
                "engine": tmp_malware['detectionEngine'],
                "detection_type": tmp_malware.get('detectionValueType', "-"),
                "detection_value": tmp_malware.get('detectionValue', "-"),
                'threat_need_attention': tmp_malware['needsAttention'],
                'severity': tmp_malware.get('score', 0.0),
                'threat_name': tmp_malware['malwareDataModel'].get('detectionName', "-"),
                'threat_fullpath': tmp_malware['malwareDataModel'].get('filePath', "-"),
                'threat_url': tmp_malware['malwareDataModel'].get('url') or "-"
            }

        # for guid, machines in tmp_machines.items():
        #     tmp_affected_machines = self.__get_affected_devices(
        #         machines,
        #         "machineName",
        #         test
        #     )
        #
        #     for device in tmp_affected_machines:
        #         malwares[guid]['affected_devices'].append(device)
        #         if test:
        #             break
        #
        #     if test:
        #         break

        for guid, value in malwares.items():
            value['guid'] = guid

            yield value

            if test:
                break

    def test(self):
        # Get logs from last 24 hours
        query_time = (datetime.datetime.now()-datetime.timedelta(days=7)).timestamp()
        try:
            status, logs = self.get_logs("malops", query_time, test=True)
            logger.info(json.dumps(logs))
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
            logger.exception(e)
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, kind, since, test=False):
        data = []
        try:
            if kind == "malops":
                for requestedType in ('MalopProcess',):
                    self.execute_query(
                        kind,
                        since,
                        test=test,
                        requestedType=requestedType
                    )

                    status, tmp_malops = self.cyber_tool.get_malops(self.query)
                    if not status:
                        raise Exception(tmp_malops)

                    for malop in self.parse_malops(tmp_malops, test):
                        data.append(malop)
                        if test:
                            break

            elif kind == "malwares":
                self.execute_query(
                    kind,
                    since,
                    test=test
                )

                status, tmp_malwares = self.cyber_tool.get_malwares(self.query)
                if not status:
                    raise Exception(tmp_malwares)

                data = []
                for malware in self.parse_malwares(tmp_malwares['data']['malwares'], test):
                    data.append(malware)
                    if test:
                        break

            return True, data

        except Exception as e:
            logger.error("[CYBEREASON PLUGIN] Error querying {} logs : ".format(kind))
            logger.exception(e)


    def execute(self):
        # Retrieve version of cybereason console
        status, version_data = self.cyber_tool.get_version()
        if not status:
            raise CybereasonAPIError("Failed to retrieve console version : {}".format(version_data))
        observer_version = version_data.get('data', {}).get('version', "0.0")

        for kind in ["malops", "malwares"]:
            logger.info("Cybereason:: Getting {} events".format(kind))

            # Default timestamp is 24 hours ago
            since = getattr(self.frontend, f"cybereason_{kind}_timestamp") or (timezone.now()-datetime.timedelta(days=1)).timestamp()
            status, tmp_logs = self.get_logs(kind, since=since)

            if not status:
                raise CybereasonAPIError(tmp_logs)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            total = len(tmp_logs)

            if total > 0:
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

        logger.info("Cybereason parser ending.")

