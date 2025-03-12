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

__author__ = "eduquennoy"
__credits__ = ["Florian Ledoux"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'CrowdStrike API Parser toolkit'
__parser__ = 'CROWDSTRIKE'

import datetime
import json
import logging
import time
from datetime import timedelta

import requests
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CrowdstrikeAPIError(Exception):
    pass


class CrowdstrikeParser(ApiParser):
    AUTH_URI = "oauth2/token"
    DEVICE_URI = "devices/queries/devices/v1"
    DETECTION_URI = "detects/queries/detects/v1"
    DETECTION_DETAILS_URI = "detects/entities/summaries/GET/v1"
    INCIDENT_URI = "incidents/queries/incidents/v1"
    INCIDENT_DETAILS_URI = "incidents/entities/incidents/GET/v1"

    HEADERS = {
        "Content-Type": "application/x-www-form-urlencoded",
        'accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.api_host = data["crowdstrike_host"].rstrip('/')
        self.client_id = data["crowdstrike_client_id"]
        self.client_secret = data["crowdstrike_client_secret"]
        self.client = data["crowdstrike_client"]

        self.product = 'crowdstrike'
        self.session = None

        self.request_incidents = data.get('crowdstrike_request_incidents', False)

        if not self.api_host.startswith('https://'):
            self.api_host = f"https://{self.api_host}"

        self.login()

    def login(self):
        logger.info(f"[{__parser__}][login]: Login in...", extra={'frontend': str(self.frontend)})
        auth_url = f"{self.api_host}/{self.AUTH_URI}"

        self.session = requests.session()
        self.session.headers.update(self.HEADERS)

        payload = {'client_id': self.client_id,
                   'client_secret': self.client_secret}
        try:
            response = self.session.post(
                auth_url,
                data=payload,
                timeout=10,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        except requests.exceptions.ConnectionError:
            self.session = None
            logger.error(f'[{__parser__}][login]: Connection failed (ConnectionError)', exc_info=True, extra={'frontend': str(self.frontend)})
            return False, ('Connection failed')
        except requests.exceptions.ReadTimeout:
            self.session = None
            logger.error(f'[{__parser__}][login]: Connection failed {self.client_id} (read_timeout)', extra={'frontend': str(self.frontend)})
            return False, ('Connection failed')

        response.raise_for_status()
        if response.status_code not in [200, 201]:
            self.session = None
            logger.error(f'[{__parser__}][login]: Authentication failed. code {response.status_code}', extra={'frontend': str(self.frontend)})
            return False, ('Authentication failed')

        ret = response.json()
        self.session.headers.update(
            {'authorization': f"{ret['token_type'].capitalize()} {ret['access_token']}"})
        del self.session.headers['Content-Type']
        del self.session.headers['Accept-Encoding']

        return True, self.session

    def __execute_query(self, method, url, query, timeout=10):
        retry = 3
        while(retry > 0):
            retry -= 1
            logger.info(f"[{__parser__}]:execute_query: URL: {url} , method: {method}, params: {query}, retry : {retry}", extra={'frontend': str(self.frontend)})
            try:
                if(method == "GET"):
                    response = self.session.get(
                        url,
                        params=query,
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                    )
                elif(method == "POST"):
                    headers = {'Content-Type': 'application/json'}
                    response = self.session.post(
                        url,
                        data=json.dumps(query),
                        headers=headers,
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                    )
            except requests.exceptions.ReadTimeout:
                time.sleep(timeout)
                continue
            break  # no error we break from the loop

        if response.status_code not in [200, 201]:
            msg = f"[{__parser__}][__execute_query]: Error at Crowdstrike API Call URL: {url} Code: {response.status_code} Content: {response.content}"
            logger.error(msg, extra={'frontend': str(self.frontend)})
            raise Exception(msg)
        return response.json()

    def unionDict(self, dictBase, dictToAdd):
        finalDict = {}
        for k, v in dictBase.items():
            if(isinstance(v, dict)):
                finalDict[k] = self.unionDict(dictBase[k], dictToAdd[k])
            elif(isinstance(v, list)):
                finalDict[k] = dictBase[k] + dictToAdd[k]
            else:
                finalDict[k] = dictToAdd[k]
        return finalDict

    def execute_query(self, method, url, query={}, timeout=10):
        # can set a custom limit of entry we want to retrieve
        customLimit = int(query.get('limit', -1))

        jsonResp = self.__execute_query(method, url, query, timeout=timeout)
        totalToRetrieve = jsonResp.get('meta', {}).get('pagination', {}).get('total', 0)

        while(totalToRetrieve > 0 and totalToRetrieve != len(jsonResp.get('resources', []))):
            # we retrieved enough data
            if(customLimit > 0 and customLimit <= len(jsonResp['resources'])):
                break
            query['offset'] = len(jsonResp['resources'])
            jsonAdditionalResp = self.__execute_query(method, url, query, timeout=timeout)
            self.update_lock()
            jsonResp = self.unionDict(jsonResp, jsonAdditionalResp)
            #jsonResp += [jsonAdditionalResp]
        return jsonResp

    def getSummary(self):
        nbSensor = self.getSensorsTotal()
        version, updated = self.getApplianceVersion()
        return nbSensor, version, updated

    def getApplianceVersion(self):
        return 0, 0

    def getSensorsTotal(self):
        device_url = f"{self.api_host}/{self.DEVICE_URI}"
        ret = self.execute_query('GET', device_url, {'limit': 1})
        return int(ret['meta']['pagination']['total'])

    def getAlerts(self, since, to):
        '''
        we retrieve raw incidents and detections
        '''
        logger.info(f"[{__parser__}][getAlerts]: From {since} until {to}",  extra={'frontend': str(self.frontend)})

        finalRawAlerts = []
        # first retrieve the detection raw ids
        alert_url = f"{self.api_host}/{self.DETECTION_URI}"
        payload = {
            "filter": f"last_behavior:>'{since}'+last_behavior:<='{to}'",
            "sort": "last_behavior|desc"
        }
        ret = self.execute_query("GET", alert_url, payload)
        ids = ret['resources']
        if(len(ids) > 0):
            # retrieve the content of detection selected
            alert_url = f"{self.api_host}/{self.DETECTION_DETAILS_URI}"
            payload = {"ids": ids}
            ret = self.execute_query("POST", alert_url, payload)

            alerts = ret['resources']
            for alert in alerts:
                finalRawAlerts += [alert]

        if self.request_incidents:
            # then retrieve the incident raw ids
            alert_url = f"{self.api_host}/{self.INCIDENT_URI}"
            payload = {
                "filter": f"start:>'{since}'+start:<='{to}'",
                "sort": "end|desc"
            }

            ret = self.execute_query("GET", alert_url, payload)
            ids = ret['resources']

            if(len(ids) > 0):
                # retrieve the content of selected incidents
                alert_url = f"{self.api_host}/{self.INCIDENT_DETAILS_URI}"
                payload = {"ids": ids}
                ret = self.execute_query("POST", alert_url, payload)
                alerts = ret['resources']
                for alert in alerts:
                    finalRawAlerts += [alert]
        return finalRawAlerts

    def get_logs(self, kind, since, to):
        msg = f"Querying {kind} from {since}, to {to}"
        logger.info(f"[{__parser__}][get_logs]: {msg}", extra={'frontend': str(self.frontend)})

        try:
            return self.getAlerts(since, to)
        except Exception as e:
            logger.exception(f"[{__parser__}][get_logs]: {e}", extra={'frontend': str(self.frontend)})
            raise Exception(f"Error querying {kind} logs")

    def format_log(self, log):
        log['kind'] = self.kind
        log['observer_version'] = self.observer_version
        log['url'] = self.api_host
        return json.dumps(log)

    def execute(self):
        # Retrieve version of cybereason console
        _, self.observer_version, _ = self.getSummary()

        self.kind = "details"
        # Default timestamp is 24 hours ago
        since = self.last_api_call or (timezone.now() - datetime.timedelta(days=7))
        # Get a batch of 24h at most, to avoid running the parser for too long
        # delay the query time of 2 minutes, to avoid missing events
        to = min(timezone.now()-timedelta(minutes=2), since + timedelta(hours=24))
        to = to.strftime("%Y-%m-%dT%H:%M:%SZ")
        since = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        tmp_logs = self.get_logs(self.kind, since=since, to=to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        total = len(tmp_logs)

        if total > 0:
            logger.info(f"[{__parser__}][execute]: Total logs fetched : {total}", extra={'frontend': str(self.frontend)})

            # Logs sorted by timestamp descending, so first is newer
            self.frontend.last_api_call = to

        elif self.last_api_call < timezone.now()-timedelta(hours=24):
            # If no logs where retrieved during the last 24hours,
            # move forward 1h to prevent stagnate ad vitam eternam
            self.frontend.last_api_call += timedelta(hours=1)

        self.write_to_file([self.format_log(log) for log in tmp_logs])

        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        logger.info(f"[{__parser__}][execute]: Parsing done.", extra={'frontend': str(self.frontend)})

    def test(self):
        try:
            logger.debug(f"[{__parser__}][test]:Running tests...", extra={'frontend': str(self.frontend)})

            query_time = (timezone.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            to = timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")

            logs = self.get_logs("details", query_time, to)

            msg = f"{len(logs)} details retrieved"
            logger.info(f"[{__parser__}][test]: {msg}", extra={'frontend': str(self.frontend)})
            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}][test]: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }
