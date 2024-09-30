# from cybereason import CybereasonParser
import json
from datetime import datetime, timedelta

from pytz import utc


class Malop:

    ALERT_URI = "rest/mmng/v2/malops"
    ALERT_DETAILS = "rest/detection/details"
    ALERT_MALOP_COMMENT_URI = "rest/crimes/get-comments"
    SENSOR_URI = "rest/sensors/query"
    DESCRIPTION_URI = "rest/translate/features/all"
    SEARCH_URI = "rest/visualsearch/query/simple"
    DESC_TRANSLATION = {}

    def __init__(self, instance: object) -> None:
        self.instance = instance

    def get_logs(self, since: datetime, to: datetime) -> (list, object, bool):
        url_alert = f'{self.instance.host}/{self.ALERT_URI}'

        query = {
            "search": {},
            "range":
                {
                    "from": int(since.timestamp()) * 1000,
                    "to": int(to.timestamp()) * 1000
                },
            "pagination": {
                "pageSize": 50,
                "offset": 0
            },
            "federation": {
                "groups": []
            },
            "sort": [
                {
                    "field": "lastUpdateTime",
                    "order": "desc"
                }
            ]
        }

        logs = []
        offset = 0
        has_more_logs = True
        last_timestamp = None
        # Get bulk of 1000 max logs
        while len(logs) < 1000:
            ret = self.instance.execute_query("POST", url_alert, query, timeout=30)
            received_logs = ret.get('data', {}).get('data', [])
            if 'data' not in ret or not received_logs:
                has_more_logs = False
                break
            logs.extend(received_logs)
            offset += len(received_logs)
            query['pagination']['offset'] = offset
            if ret.get('status') != 'SUCCESS' or offset >= ret.get('data', {}).get('totalHits', 0):
                has_more_logs = False
                break
        if logs:
            # Make sure logs are sorted by timestamps
            # ISO8601 timestamps are sortable as strings
            last_timestamp = max(x['lastUpdateTime'] for x in logs)
            last_timestamp = datetime.fromtimestamp(int(last_timestamp) / 1000, tz=utc)

        return logs, last_timestamp, has_more_logs

    def add_enrichment(self, alert: dict) -> dict:
        alert['id'] = alert['guid']
        alert['url'] = self.instance.host

        suspicions_process, suspicions_network = self._suspicions(alert['id'], alert['lastUpdateTime'])
        suspicions = list(suspicions_process.get('data', {}).get('suspicionsMap', {}).keys())
        suspicions.extend(list(suspicions_network.get('data', {}).get('suspicionsMap', {}).keys()))
        alert['suspicion_list'] = suspicions

        if alert['isEdr']:
            alert['kind'] = 'malops'
            alert['comments'] = self._get_comments(alert['id'])
            alert['process_details'] = suspicions_process.get('data', {}).get('resultIdToElementDataMap', {})

            machine_guids = [
                machine["guid"]
                for data in alert.get('process_details', {}).values()
                for machine in data.get('elementValues', {}).get('ownerMachine', {}).get('elementValues')
            ]

        else:
            alert['kind'] = 'detection-malops'
            start_date = alert['lastUpdateTime'] - 30 * 24 * 60 * 60 * 1000
            alert['malop_details'] = self._get_malop_detection_details(alert['guid'], start_date)

            machine_guids = [
                machine["guid"]
                for machine in alert.get('malop_details', {}).get('machines', [])
            ]

        # Requesting may take some while, so refresh token in Redis
        self.instance.update_lock()

        alert_devices_details = self._get_sensors(machine_guids)

        # Requesting may take some while, so refresh token in Redis
        self.instance.update_lock()

        alert['devices'] = []
        for devices in alert_devices_details:
            alert['devices'] += [{
                "nat": {
                    "ip": devices.get("internalIpAddress", '-'),
                },
                "hostname": devices.get("machineName", '-'),
                "os": {
                    "full": devices.get("osVersionType", '-')
                },
                "ip": devices.get("externalIpAddress", '-'),
                "id": devices.get("sensorId", '-'),
                "policy": devices.get("policyName", '-'),
                "group": devices.get("groupName", '-'),
                "site": devices.get("siteName", '-'),
                "version": devices.get("version", '-'),
                "organization": devices.get("organization", '-'),
                "adOU": devices.get("organizationalUnit", '-'),
                "domain": devices.get("fqdn", '-'),
                "domainFqdn": devices.get("organization", '-')
            }]

        alert['machines'] = []
        return alert

    def format_log(self, log: dict) -> json:
        log['iconBase64'] = ""

        flattened_ip = []
        flattened_hostname = []
        flattened_domain = []

        for device in log['devices']:
            if device['ip'] not in flattened_ip:
                flattened_ip.append(device['ip'])
            if device['nat']['ip'] not in flattened_ip:
                flattened_ip.append(device['nat']['ip'])
            if device['hostname'] not in flattened_hostname:
                flattened_hostname.append(device['hostname'])
            if device['domain'] not in flattened_domain:
                flattened_domain.append(device['domain'])

        for user in log['users']:
            domain = (user['displayName']).split('\\')[0]
            if domain not in flattened_domain:
                flattened_domain.append(domain)

        if process_details := log.get('process_details'):
            log['formated_process_details'] = self._process_details_flattener(process_details)

            log['flattened_cmdline'] = list({v for i in log['formated_process_details'] for v in i['cmdline']})
            log['flattened_hash_md5'] = list({v for i in log['formated_process_details'] for v in i['hash']['md5']})
            log['flattened_hash_sha1'] = list({v for i in log['formated_process_details'] for v in i['hash']['sha1']})
            log['flattened_hash_sha256'] = list({v for i in log['formated_process_details'] for v in i['hash']['sha256']})

        if malop_details := log.get('malop_details'):
            log['formated_malops_details'] = self._malops_details_flattener(malop_details)
            log['flattened_hash_sha1'] = list({i['hash']['sha1'] for i in log['formated_malops_details']})

        log['flattened_ip'] = flattened_ip
        log['flattened_hostname'] = flattened_hostname
        log['flattened_domain'] = flattened_domain
        return json.dumps(log)

    def _get_malop_detection_details(self, alert_id: str, start_date:int) -> dict:
        query = {
            "malopGuid": alert_id
        }
        url = f"{self.instance.host}/{self.ALERT_DETAILS}"
        details = self.instance.execute_query("POST", url, query)

        if details.get('fileSuspects', []):
            suspects = [
                suspect
                for suspect in details.get('fileSuspects', [])
                if suspect.get('lastSeen', start_date) >= start_date
            ]

            details['fileSuspects'] = suspects
            details['filePaths'] = list(set(file_.get('correctedPath', '') for file_ in suspects))
            details['files'] = [
                file_
                for file_ in details.get('files', [])
                if file_.get('guid', '') in [suspect.get('guid', '') for suspect in suspects]
            ]
            details['machines'] = [
                machine
                for machine in details.get('machines', [])
                if machine.get('guid', '') in [suspect.get('ownerMachineGuid', '') for suspect in suspects]
            ]

        if details.get('processSuspects', []):
            suspects = [
                suspect
                for suspect in details.get('processSuspects', [])
                if suspect.get('lastSeen', start_date) >= start_date
            ]

            details['processSuspects'] = suspects
            details['commandLines'] = list(set(process.get('commandLine', '') for process in suspects))
            details['processes'] = [
                process
                for process in details.get('processes', [])
                if process.get('guid', '') in [suspect.get('guid', '') for suspect in suspects]
            ]
            details['machines'] = [
                machine
                for machine in details.get('machines', [])
                if machine.get('displayName', '') in [suspect.get('ownerMachine', '') for suspect in suspects]
            ]
            details['users'] = [
                user
                for user in details.get('users', [])
                if user.get('displayName', '') in [suspect.get('calculatedUser', '') for suspect in suspects]
            ]

        return details

    def _get_comments(self, alert_malop_id: str) -> dict:

        url_alert_malop_comments = f'{self.instance.host}/{self.ALERT_MALOP_COMMENT_URI}'

        header = {
            'Content-Type': 'text/plain'
        }
        return self.instance.execute_query(method="POST", url=url_alert_malop_comments, data=alert_malop_id, header=header)

    @staticmethod
    def _process_details_flattener(process_details: dict) -> list:
        flattened_process_details = [
            {
                'name': v['simpleValues'].get('imageFile.name', {}).get('values', []),
                'cmdline': v['simpleValues'].get('commandLine', {}).get('values', []),
                'hash': {
                    'md5': v['simpleValues'].get('imageFile.md5String', {}).get('values', []),
                    'sha1': v['simpleValues'].get('imageFile.sha1String', {}).get('values', []),
                    'sha256': v['simpleValues'].get('imageFile.sha256String', {}).get('values', []),
                },
                'signature': {
                    'product_name': v['simpleValues'].get('imageFile.productName', {}).get('values', []),
                    'company_name': v['simpleValues'].get('imageFile.companyName', {}).get('values', []),
                },
                'parent': {
                    'name': v['simpleValues'].get('parentProcess.name', {}).get('values', []),
                    'machine': v['simpleValues'].get('ownerMachine.name', {}).get('values', []),
                },
            } for v in process_details.values()
        ]
        return flattened_process_details

    @staticmethod
    def _malops_details_flattener(malop_details: dict) -> list:
        flattened_process_details = [
            {
                "name": i.get('elementDisplayName', ''),
                "path": i.get('correctedPath', ''),
                "hash": {"sha1": i.get('sha1String', '')},
                "machine": {"hostname": i.get('ownerMachineName', '')},
                "action": i.get('detectionDecisionStatus', ''),
                "last_seen": i.get('lastSeen', ''),
            } for i in malop_details.get('fileSuspects', []) or []
        ]
        return flattened_process_details

    def _get_sensors(self, guids: list) -> list:
        sensors_url = f"{self.instance.host}/{self.SENSOR_URI}"
        query = {
            'limit': 100,
            'offset': 0,
            'sortDirection': 'ASC',
            'sortingFieldName': 'machineName',
            'filters': [
                {'fieldName': "guid", 'operator': 'Equals', 'values': guids},
                {"fieldName": "status", "operator": "NotEquals", "values": ["Archived"]}
            ]
        }
        data = self.instance.execute_query("POST", sensors_url, query)
        return data.get('sensors', [])

    def _suspicions(self, alert_id: str, last_update_time: int) -> (dict, dict):

        if len(self.DESC_TRANSLATION) <= 0:
            url = f"{self.instance.host}/{self.DESCRIPTION_URI}"
            self.DESC_TRANSLATION = self.instance.execute_query("GET", url)

        process_status, suspicions_process = self._suspicions_process(alert_id, last_update_time)
        network_status, suspicions_network = self._suspicions_network(alert_id)

        return (suspicions_process, suspicions_network) if all([process_status, network_status]) else ({}, {})

    def _suspicions_process(self, alert_id: str, last_update_time: int) -> (bool, dict):
        query = {
            "queryPath": [{
                "requestedType": "MalopProcess",
                "guidList": [alert_id],
                "connectionFeature": {
                    "elementInstanceType": "MalopProcess",
                    "featureName": "suspects"
                }
            }, {
                "requestedType": "Process",
                "filters": [
                    # last_update_time - 30 day (30 day in microseconds: 30 * 24 * 60 * 60 * 1000)
                    {'facetName': 'creationTime', 'filterType': 'GreaterOrEqualsTo', 'values': [last_update_time - 30 * 24 * 60 * 60 * 1000]}
                ],
                "isResult": True
            }],
            "totalResultLimit": 100,
            "perGroupLimit": 100,
            "perFeatureLimit": 100,
            "templateContext": "SPECIFIC",
            "queryTimeout": 120000,
            'sortingFacetName': 'creationTime',
            'sortDirection': 'DESC',
            'customFields': [
                'creationTime',
                'commandLine',
                'ownerMachine',
                'user.name',
                'parentProcess.name',
                'imageFile.name',
                'imageFile.sha1String',
                'imageFile.md5String',
                'imageFile.sha256String',
                'imageFile.companyName',
                'imageFile.productName'
            ]
        }

        url = f"{self.instance.host}/{self.SEARCH_URI}"
        data = self.instance.execute_query("POST", url, query)
        if data.get('status', '') != 'SUCCESS':
            return False, data.get('message', '')
        return True, data

    def _suspicions_network(self, alert_id: str) -> (bool, dict):
        query = {
            "queryPath": [{
                "requestedType": "MalopProcess",
                "filters": [],
                "guidList": [alert_id],
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

        url = f"{self.instance.host}/{self.SEARCH_URI}"
        data = self.instance.execute_query("POST", url, query)
        if data['status'] != 'SUCCESS':
            return False, data['message']
        return True, data