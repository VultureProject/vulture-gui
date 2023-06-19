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
__credits__ = ["Florian Ledoux", "Antoine Lucas", "Julien Pollet", "Nicolas Lançon"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cybereason API Parser toolkit'
__parser__ = 'CYBEREASON'


from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone

import json
import logging
from datetime import timedelta
import requests
import time

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CybereasonAPIError(Exception):
    pass


class CybereasonParser(ApiParser):

    LOGIN_URI = "login.html"
    ALERT_URI = "rest/detection/inbox"
    ALERT_MALOP_COMMENT_URI = "rest/crimes/get-comments"
    MALWARE_URI = "rest/malware/query"
    SEARCH_URI = "rest/visualsearch/query/simple"
    DESCRIPTION_URI = "rest/translate/features/all"
    SENSOR_URI = "rest/sensors/query"
    APP_VERSION_URI = "rest/monitor/global/server/version/all"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    DESC_TRANSLATION = {}

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
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                )
                response.raise_for_status()
                if "app-login" in response.content.decode('utf-8'):
                    raise CybereasonAPIError(f"Authentication failed on {login_url} for user {self.username}")
                logger.info(f"[{__parser__}]:_connect: Successfully logged-in",
                            extra={'frontend': str(self.frontend)})

            return True

        except Exception as err:
            raise CybereasonAPIError(err)

    def execute_query(self, method, url, query=None, header=HEADERS, data=None, sleepretry=10, timeout=10):
        self._connect()

        response = None
        retry = 3
        while retry > 0:
            retry -= 1

            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=query,
                    headers=header,
                    data=data,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl,
                    timeout=timeout
                )
            except requests.exceptions.ReadTimeout:
                msg = f"ReadTimeout, waiting {sleepretry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleepretry)
                continue
            except requests.exceptions.ConnectionError:
                msg = f"ConnectionError, waiting {sleepretry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleepretry)
                continue
            if response.status_code != 200:
                msg = f"Status Code {response.status_code}, waiting {sleepretry}s before retrying"
                logger.info(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
                time.sleep(sleepretry)
                continue
            break  # no error we break from the loop

        if response is None:
            msg = f"Error Cybereason API Call URL: {url} [TIMEOUT]"
            logger.error(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
            return {}
        elif response.status_code != 200:
            msg = f"Error Cybereason API Call URL: {url} [TIMEOUT], Code: {response.status_code}"
            logger.error(f"[{__parser__}]:execute_query: {msg}", extra={'frontend': str(self.frontend)})
            return {}
        return json.loads(response.content)

    def test(self):
        try:
            # Get logs from last 2 days
            to = timezone.now()
            since = (to - timedelta(hours=24))

            logs = [self.get_logs(kind, since, to) for kind in ["malops", "malwares"]]

            msg = f"{len(logs)} alert(s) retrieved"
            logger.info(f"[{__parser__}]:test: {msg}", extra={'frontend': str(self.frontend)})

            return {
                "status": True,
                "data": json.dumps(logs)
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_malops(self, since, to):
        url_alert = self.host + '/' + self.ALERT_URI

        query = {
            "startTime": int(since.timestamp()) * 1000,
            "endTime": int(to.timestamp()) * 1000
        }
        logs = self.execute_query("POST", url_alert, query, timeout=30)
        return logs.get("malops", [])

    def get_malwares(self, since):
        malware_uri = f"{self.host}/{self.MALWARE_URI}"

        query = {
            'filters': [{
                'fieldName': 'timestamp',
                'operator': 'GreaterThan',
                'values': [int(since.timestamp()) * 1000]
            }],
            'limit': 1000,
            'offset': 0,
            'search': '',
            'sortDirection': 'DESC',
            'sortingFieldName': 'timestamp'
        }

        logs = []
        offset = 0
        while True:
            ret = self.execute_query("POST", malware_uri, query)
            if 'data' not in ret:
                break
            logs.extend(ret['data']['malwares'])
            if ret['status'] != 'SUCCESS' or not ret['data']['hasMoreResults']:
                break
            offset += 1
            query['offset'] = offset
        return logs

    def get_logs(self, kind, since, to):
        try:
            if kind == "malops":
                logs = self.get_malops(since, to)
            elif kind == "malwares":
                logs = self.get_malwares(since)
            else:
                raise ValueError(f"Unknown kind {kind}")
        except Exception as err:
            msg = f"Error querying {kind} logs : {err}"
            raise CybereasonAPIError(msg)
        else:
            return logs

    def add_enrichment(self, kind, alert):
        alert['id'] = alert['guid']
        alert['url'] = self.host

        if kind == "malops":

            if alert['edr']:
                alert['kind'] = 'malops'
                alert['comments'] = self.get_comments(alert['id'])
            else:
                alert['kind'] = 'detection-malops'

            # Requesting may take some while, so refresh token in Redis
            self.update_lock()

            alert['suspicion_list'] = self.suspicions(alert['id'])
            # Keep only 100 devices
            devices_names = [machine['displayName'] for machine in alert['machines'][:100]]

            # Requesting may take some while, so refresh token in Redis
            self.update_lock()

            alert_devices_details = self.get_devices_details(devices_names)

            # Requesting may take some while, so refresh token in Redis
            self.update_lock()

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

        elif kind == "malwares":
            alert['kind'] = 'malwares'

        return alert

    def get_comments(self, alert_malop_id):

        url_alert_malop_comments = self.host + '/' + self.ALERT_MALOP_COMMENT_URI

        header = {
            'Content-Type': 'text/plain'
        }
        return self.execute_query(method="POST", url=url_alert_malop_comments, data=alert_malop_id, header=header)

    def suspicions(self, alert_id):

        if not (len(self.DESC_TRANSLATION) > 0):
            url = self.host + "/" + self.DESCRIPTION_URI
            self.DESC_TRANSLATION = self.execute_query("GET", url)

        status, suspicions_process = self.suspicions_process(alert_id)
        if not status:
            return []

        status, suspicions_network = self.suspicions_network(alert_id)
        if not status:
            return []

        suspicions = [key for key in suspicions_process['data']['suspicionsMap'].keys()]
        suspicions.extend([key for key in suspicions_network['data']['suspicionsMap'].keys()])
        return suspicions

    def suspicions_process(self, alert_id):
        # cyb.suspicions('11.-2981478659050288999')
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
        if data['status'] != 'SUCCESS':
            return False, data['message']
        return True, data

    def suspicions_network(self, alert_id):
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

        url = f"{self.host}/{self.SEARCH_URI}"
        data = self.execute_query("POST", url, query)
        if data['status'] != 'SUCCESS':
            return False, data['message']
        return True, data

    def get_devices_details(self, devices_names):
        sensors_url = f"{self.host}/{self.SENSOR_URI}"
        query = {
            'sortDirection': 'ASC',
            'sortingFieldName': 'machineName',
            'filters': [
                {'fieldName': "machineName", 'operator': "ContainsIgnoreCase", 'values': devices_names},
                {"fieldName": "status", "operator":"NotEquals", "values":["Archived"]}
            ]
        }
        data = self.execute_query("POST", sensors_url, query)
        return data.get('sensors', [])

    @staticmethod
    def format_log(kind, log):

        if kind == "malops":
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

            log['flattened_ip'] = flattened_ip
            log['flattened_hostname'] = flattened_hostname
            log['flattened_domain'] = flattened_domain
        elif kind == "malwares":
            log['original_timestamp'] = log.pop("timestamp")

        return json.dumps(log)

    def execute(self):
        # Get last api call or 30 days ago
        since = self.frontend.last_api_call or (timezone.now() - timedelta(days=30))
        # 24h max per request
        to = min(timezone.now(), since + timedelta(hours=24))

        # delay the times of 5 minutes, to let the times at the API to have all logs
        to = to - timedelta(minutes=5)

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        for kind in ["malops", "malwares"]:
            logs = self.get_logs(kind, since, to)

            # Downloading may take some while, so refresh token in Redis
            self.update_lock()

            enriched_logs = [
                self.format_log(kind, self.add_enrichment(kind, log))
                for log in logs
            ]

            # Enriching may take some while, so refresh token in Redis
            self.update_lock()

            self.write_to_file(enriched_logs)
            # Writting may take some while, so refresh token in Redis
            self.update_lock()

        # update last_api_call only if logs are retrieved
        self.frontend.last_api_call = to

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
