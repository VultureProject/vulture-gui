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
    # DEVICE_URI = "devices/queries/devices/v1"
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

        logger.info(f"[{__parser__}]:execute_query: RESPONSE: {response.text}", extra={'frontend': str(self.frontend)})


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
        # query['limit'] = 100

        jsonResp = self.__execute_query(method, url, query, timeout=timeout)
        totalToRetrieve = jsonResp.get('meta', {}).get('pagination', {}).get('total', 0)

        if totalToRetrieve > 0:
            # Continue to paginate while totalToRetrieve is different than the length of all logs gathered from successive paginations
            # The default page size is 100 (when "limit" parameter is not passed to query, like the case here)
            while(totalToRetrieve != len(jsonResp.get('resources', []))):
                query['offset'] = len(jsonResp.get('resources', []))

                jsonAdditionalResp = self.__execute_query(method, url, query, timeout=timeout)
                self.update_lock()

                jsonResp = self.unionDict(jsonResp, jsonAdditionalResp)

        return jsonResp


    def get_detections(self, since, to):
        logger.debug(f"[{__parser__}][get_detections]: From {since} until {to}",  extra={'frontend': str(self.frontend)})

        detections = []
        # first retrieve the detections raw ids
        ret = self.execute_query(method="GET",
                                 url=f"{self.api_host}/{self.DETECTION_URI}",
                                 query={
                                    "filter": f"last_behavior:>'{since}'+last_behavior:<='{to}'",
                                    "sort": "last_behavior|desc"
                                 })
        ids = ret['resources']
        # then retrieve the content of selected detections ids
        if(len(ids) > 0):
            ret = self.execute_query(method="POST",
                                     url=f"{self.api_host}/{self.DETECTION_DETAILS_URI}",
                                     query={"ids": ids})
            ret = ret['resources']
            for alert in ret: detections += [alert]
        return detections


    def get_incidents(self, since, to):
        logger.debug(f"[{__parser__}][get_incidents]: From {since} until {to}",  extra={'frontend': str(self.frontend)})

        incidents = []
        # first retrieve the incidents raw ids
        ret = self.execute_query(method="GET",
                                 url=f"{self.api_host}/{self.INCIDENT_URI}",
                                 query={
                                    "filter": f"start:>'{since}'+start:<='{to}'",
                                    "sort": "end|desc"
                                 })
        ids = ret['resources']
        # then retrieve the content of selected incidents ids
        if(len(ids) > 0):
            ret = self.execute_query(method="POST",
                                     url=f"{self.api_host}/{self.INCIDENT_DETAILS_URI}",
                                     query={"ids": ids})
            ret = ret['resources']
            for alert in ret: incidents += [alert]
        return incidents


    def get_logs(self, kind, since, to):
        logs = []

        msg = f"Querying {kind} from {since}, to {to}"
        logger.info(f"[{__parser__}][get_logs]: {msg}", extra={'frontend': str(self.frontend)})
        try:
            get_func_type = getattr(self, f"get_{kind}") # get_detections/get_incidents function getter
            logs = get_func_type(since, to)
        except Exception as e:
            logger.exception(f"[{__parser__}][get_logs]: {e}", extra={'frontend': str(self.frontend)})
            raise Exception(f"Error querying {kind} logs")

        return logs


    def format_log(self, log):
        log['url'] = self.api_host
        return json.dumps(log)

    def test(self):
        try:
            self.login() # establish a session to console

            logger.info(f"[{__parser__}][test]:Running tests...", extra={'frontend': str(self.frontend)})

            since = (timezone.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            to = timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")

            logs = []
            logs += self.get_logs("detections", since, to)
            if self.request_incidents: logs += self.get_logs("incidents", since, to)

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

        kinds = ["detections"]
        if self.request_incidents: kinds.append("incidents")

        for kind in kinds:
            # Default timestamp is 24 hours ago
            since = self.last_collected_timestamps.get(f"crowdstrike_falcon_{kind}") or (timezone.now() - datetime.timedelta(days=7))
            # Get a batch of 24h at most, to avoid running queries for too long
            # also delay the query time of 3 minutes, to avoid missing events
            to = min(timezone.now()-timedelta(minutes=3), since + timedelta(hours=24))

            logs = self.get_logs(kind=kind,
                                 since=since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                 to=to.strftime("%Y-%m-%dT%H:%M:%SZ"))
            total = len(logs)

            if total > 0:
                logger.info(f"[{__parser__}][execute]: Total logs fetched : {total}", extra={'frontend': str(self.frontend)})
                self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] = to

            elif not self.last_collected_timestamps.get(f"crowdstrike_falcon_{kind}"):
                    # If last_collected_timestamps for the kind requested doesn't exists
                    # (possible in case we don't get logs for the next period of time at first collector execution)
                    self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] = to

            elif self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] < timezone.now()-timedelta(hours=24):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] += timedelta(hours=1)

            self.write_to_file([self.format_log(log) for log in logs])
            self.update_lock()

        logger.info(f"[{__parser__}][execute]: Parsing done.", extra={'frontend': str(self.frontend)})