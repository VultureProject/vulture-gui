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

        self.request_incidents = data.get('crowdstrike_request_incidents', False)

        self.session = None

        if not self.api_host.startswith('https://'):
            self.api_host = f"https://{self.api_host}"


    def login(self):
        logger.info(f"[{__parser__}][login]: Login in...", extra={'frontend': str(self.frontend)})

        self.session = requests.session()
        self.session.headers.update(self.HEADERS)

        try:
            # Rate limiting seems to be 10/minute for the authentication endpoint
            response = self.session.post(
                url=f"{self.api_host}/{self.AUTH_URI}",
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                },
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
            logger.error(f'[{__parser__}][login]: Connection failed (ReadTimeout)', extra={'frontend': str(self.frontend)})
            return False, ('Connection failed')

        response.raise_for_status()
        if response.status_code not in [200, 201]:
            self.session = None
            logger.error(f'[{__parser__}][login]: Authentication failed. Status code {response.status_code}', extra={'frontend': str(self.frontend)})
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
                    response = self.session.post(
                        url,
                        data=json.dumps(query),
                        headers={'Content-Type': 'application/json'},
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                    )
            except requests.exceptions.ReadTimeout:
                time.sleep(timeout)
                continue
            break  # no error we break from the loop

        if response.status_code not in [200, 201]:
            logger.error(f"[{__parser__}][__execute_query]: Error at Crowdstrike API Call URL: {url} Code: {response.status_code} Content: {response.content}",
                         extra={'frontend': str(self.frontend)})
            return {}
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
        # Setting a custom limit to -1 by default ensuring line 178 to not break on first page collection.
        # The result per page is 100 by default for this API (when not using limit as it is the case here).
        customLimit = int(query.get('limit', -1))

        jsonResp = self.__execute_query(method, url, query, timeout=timeout)
        totalToRetrieve = jsonResp.get('meta', {}).get('pagination', {}).get('total', 0)

        while(totalToRetrieve > 0 and totalToRetrieve != len(jsonResp.get('resources', []))):
            # if we've retrieved enough data -> break
            if(customLimit > 0 and customLimit <= len(jsonResp['resources'])): break

            query['offset'] = len(jsonResp.get('resources', []))
            jsonAdditionalResp = self.__execute_query(method, url, query, timeout=timeout)

            jsonResp = self.unionDict(jsonResp, jsonAdditionalResp)
        return jsonResp


    def get_detections(self, since, to):
        logger.debug(f"[{__parser__}][get_detections]: From {since} until {to}",  extra={'frontend': str(self.frontend)})

        detections = []
        # first retrieve the detections raw ids
        payload = {
            "filter": f"last_behavior:>'{since}'+last_behavior:<='{to}'",
            "sort": "last_behavior|desc"
        }
        ret = self.execute_query("GET",
                                 f"{self.api_host}/{self.DETECTION_URI}",
                                 payload)
        ids = ret['resources']
        # then retrieve the content of selected detections ids
        if(len(ids) > 0):
            ret = self.execute_query(method="POST",
                                     url=f"{self.api_host}/{self.DETECTION_DETAILS_URI}",
                                     query={"ids": ids})
            alerts = ret['resources']
            for alert in alerts:
                detections += [alert]
        return detections

    def get_incidents(self, since, to):
        logger.debug(f"[{__parser__}][get_incidents]: From {since} until {to}",  extra={'frontend': str(self.frontend)})

        incidents = []
        # first retrieve the incidents raw ids
        payload = {
            "filter": f"start:>'{since}'+start:<='{to}'",
            "sort": "end|desc"
        }
        ret = self.execute_query("GET",
                                 f"{self.api_host}/{self.INCIDENT_URI}",
                                 payload)
        ids = ret['resources']
        # then retrieve the content of selected incidents ids
        if(len(ids) > 0):
            ret = self.execute_query(method="POST",
                                        url=f"{self.api_host}/{self.INCIDENT_DETAILS_URI}",
                                        query={"ids": ids})
            alerts = ret['resources']
            for alert in alerts:
                incidents += [alert]
        return incidents

    def get_logs(self, since, to):
        logs = []

        kinds = ["detections"]
        if self.request_incidents:
            kinds.append("incidents")
        for kind in kinds:
            try:
                msg = f"Querying {kind} from {since}, to {to}"
                logger.info(f"[{__parser__}][get_logs]: {msg}", extra={'frontend': str(self.frontend)})
                get_func_type = getattr(self, f"get_{kind}")
                logs.extend(get_func_type(since, to))

            except Exception as e:
                logger.exception(f"[{__parser__}][get_logs]: {e}", extra={'frontend': str(self.frontend)})
                raise Exception(f"Error querying {kind} logs")
        return logs

    def format_log(self, log):
        log['url'] = self.api_host # This static field is mandatory for parser
        return json.dumps(log)


    def test(self):
        try:
            self.login() # establish a session to console
            logger.info(f"[{__parser__}][test]:Running tests...", extra={'frontend': str(self.frontend)})

            since = (timezone.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            to = timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")

            logs = self.get_logs(since, to)

            msg = f"{len(logs)} logs retrieved"
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


    def execute(self):
        self.login() # establish a session to console

        # Default timestamp is 24 hours ago
        since = self.last_api_call or (timezone.now() - datetime.timedelta(days=7))
        # Get a batch of 24h at most, to avoid running queries for too long
        # also delay the query time of 3 minutes, to avoid missing events
        to = min(timezone.now()-timedelta(minutes=3), since + timedelta(hours=24))
        to = to.strftime("%Y-%m-%dT%H:%M:%SZ")
        since = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        logs = self.get_logs(since=since, to=to)
        self.update_lock()

        total = len(logs)
        if total > 0:
            logger.info(f"[{__parser__}][execute]: Total logs fetched : {total}", extra={'frontend': str(self.frontend)})
            self.frontend.last_api_call = to # Logs sorted by timestamp descending, so first is newer

        # If no logs where retrieved during the last 24hours,
        # move forward 1h to prevent stagnate ad vitam eternam
        elif self.last_api_call < timezone.now()-timedelta(hours=24):
            self.frontend.last_api_call += timedelta(hours=1)

        self.write_to_file([self.format_log(log) for log in logs])
        self.update_lock()

        logger.info(f"[{__parser__}][execute]: Parsing done.", extra={'frontend': str(self.frontend)})
