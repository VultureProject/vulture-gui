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

import logging
from json import dumps, JSONDecodeError
from datetime import timedelta
from requests import session
from requests.exceptions import ConnectionError, ReadTimeout

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CrowdstrikeAPIError(Exception):
    pass


class CrowdstrikeParser(ApiParser):
    AUTH_URI = "oauth2/token"
    ALERTS_URI = "alerts/queries/alerts/v2"
    ALERTS_DETAILS_URI = "alerts/entities/alerts/v2"
    DEVICE_DETAILS_URI = "devices/entities/devices/v2"

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

        self.session = None

        self.request_incidents = data.get('crowdstrike_request_incidents', False)

        self.api_host = "https://" + self.api_host.split('://')[-1]


    def login(self) -> tuple:
        logger.info(f"[{__parser__}][login]: Login in...", extra={'frontend': str(self.frontend)})
        auth_url = f"{self.api_host}/{self.AUTH_URI}"

        self.session = session()
        self.session.headers.update(self.HEADERS)

        auth_payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        try:
            response = self.session.post(
                auth_url,
                data=auth_payload,
                timeout=10,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
            )
        except ConnectionError:
            self.session = None
            logger.error(f'[{__parser__}][login]: Connection failed (ConnectionError)', exc_info=True, extra={'frontend': str(self.frontend)})
            return False, ('Connection failed')
        except ReadTimeout:
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


    def __execute_query(self, method: str, url: str, query: dict, timeout: int = 10) -> dict:
        retry = 3
        response = None
        while retry > 0 and not self.evt_stop.is_set():
            retry -= 1
            logger.info(f"[{__parser__}][__execute_query]: URL: {url} , method: {method}, params: {query}, retry : {retry}", extra={'frontend': str(self.frontend)})
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
                        data=dumps(query),
                        headers={'Content-Type': 'application/json'},
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
                    )
            except ReadTimeout:
                self.evt_stop.wait(timeout)
                continue
            break  # no error we break from the loop

        if not response:
            logger.error(f"[{__parser__}][__execute_query]: No response while querying API", extra={'frontend': str(self.frontend)})
            raise CrowdstrikeAPIError("No Response")
        elif response.status_code not in [200, 201]:
            msg = f"[{__parser__}][__execute_query]: Error at Crowdstrike API Call URL: {url} Code: {response.status_code} Content: {response.content}"
            logger.error(msg, extra={'frontend': str(self.frontend)})
            raise CrowdstrikeAPIError(msg)

        try:
            resp = response.json()
        except JSONDecodeError as e:
            logger.warning(f"[{__parser__}][__execute_query]: Could not decode JSON from query: {e}", extra={'frontend': str(self.frontend)})
            resp = {}

        return resp


    def get_ids(self, query: dict, timeout: int = 10) -> list:
        """
        Aim to gather ids from various Crowdstrike Falcon endpoints
        before requesting the logs using those ids
        """
        ret = []
        # can set a custom limit of entry we want to retrieve for a single request
        query['limit'] = 1000
        url = f"{self.api_host}/{self.ALERTS_URI}"

        jsonResp = self.__execute_query("GET", url, query, timeout=timeout)
        totalToRetrieve = jsonResp.get('meta', {}).get('pagination', {}).get('total', 0)

        if totalToRetrieve > 0:
            ret.extend(jsonResp.get('resources', []))
            # Continue to paginate while totalToRetrieve is different than the length of all logs gathered from successive paginations
            # The default page size is 100 (when "limit" parameter is not passed to query)
            while(totalToRetrieve > len(ret)):
                query['offset'] = len(ret)

                jsonResp = self.__execute_query("GET", url, query, timeout=timeout)
                # it's better to retrieve meta.pagination.total for every requests
                # as some endpoints could returns variable output length as time vary
                totalToRetrieve = jsonResp.get('meta', {}).get('pagination', {}).get('total', 0)
                self.update_lock()

                ret.extend(jsonResp.get('resources', []))

        return ret


    def split_chunks(self, resources: list) -> list[list]:
        """
        Serve to split ids in a list of chunks that not exceed 1000 entries with the form : [[chunk1], [chunk2]]
        As detections/incidents endpoints have limit of result fetchable in a single request
        """
        chunks = []
        resourcesLen = len(resources)
        if resourcesLen >= 1000:
            i = 0
            tmp_logs = []
            while i < resourcesLen:
                tmp_logs.append(resources[i])
                i+=1
                if i != 0 and i % 1000 == 0:
                    chunks.append(tmp_logs)
                    tmp_logs = []
            chunks.append(tmp_logs) # append last logs occurence
        elif resourcesLen > 0:
            chunks.append(resources)

        return chunks


    def get_detections(self, since: str, to: str) -> list:
        """
        Get detections logs (using product parameter in query to filter out incidents)
        """
        logger.debug(f"[{__parser__}][get_detections]: From {since} until {to}",  extra={'frontend': str(self.frontend)})
        detections = []

        # first retrieve the detections raw ids
        filter = f"updated_timestamp:>'{since}'"
        filter += f"+updated_timestamp:<='{to}'"
        filter += "+data_domains:'Endpoint'"
        filter += "+product:['epp', 'ngsiem', 'thirdparty']"
        ids = self.get_ids(query={
                                "filter": filter,
                                "sort": "updated_timestamps|asc",
                                "include_hidden": False
                            })
        chunks = self.split_chunks(ids)
        # then retrieve the content of selected detections ids
        if(len(chunks) > 0):
            for chunk in chunks:
                ret = self.__execute_query(
                    "POST",
                    f"{self.api_host}/{self.ALERTS_DETAILS_URI}",
                    query={
                        "composite_ids": chunk,
                        "sort": "updated_timestamp|desc"
                    })
                detections.extend(ret.get('resources', []))
        return detections


    def get_incidents(self, since: str, to: str) -> list:
        """
        Get incidents logs (using product parameter in query to filter out detections)
        """
        logger.debug(f"[{__parser__}][get_incidents]: From {since} until {to}",  extra={'frontend': str(self.frontend)})
        incidents = []

        # first retrieve the incidents raw ids
        filter = f"updated_timestamp:>'{since}'"
        filter += f"+updated_timestamp:<='{to}'"
        filter += "+data_domains:'Endpoint'"
        filter += "+product:['xdr']"
        ids = self.get_ids(query={
                            "filter": filter,
                            "sort": "updated_timestamp|asc",
                            "include_hidden": False
                            })
        chunks = self.split_chunks(ids)
        # then retrieve the content of selected incidents ids
        if(len(chunks) > 0):
            for chunk in chunks:
                ret = self.__execute_query(
                    "POST",
                    f"{self.api_host}/{self.ALERTS_DETAILS_URI}",
                    query={
                        "composite_ids": chunk,
                        "sort": "updated_timestamp|desc"
                    })
                incidents.extend(ret.get('resources', []))
        return incidents


    def get_logs(self, kind: str, since: str, to: str) -> list:
        """
        Used to retrieve get_detections() and get_incidents() funcs + loggers
        """
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


    def get_devices(self, ids: list) -> list:
        """
        Used to enrich .hosts field by querying devices with ids found for incidents in the field .entities.agent_ids
        """
        devices = self.__execute_query(method="POST",
                                url=f"{self.api_host}/{self.DEVICE_DETAILS_URI}",
                                query={"ids": ids})
        return devices.get('resources', [])


    def format_log(self, log: dict) -> str:
        """
        Used to prepare/format one log entry for writing to rsyslog
        Note that product is used to determine log-types and subsequent enrichments/retro-compatibility
        """
        product = log.get("product")
        # this ensure the retro-compatibility of detections logs that contains .behaviors object
        if product in ["epp", "ngsiem", "thirdparty"]:
            behaviors = {}
            for field in ["alleged_filetype", "behavior_id", "cmdline", "confidence", "control_graph_id",
                            "description", "agent_id", "display_name", "filename", "filepath", "ioc_description",
                            "ioc_source", "ioc_type", "ioc_value", "md5", "objective", "parent_details",
                            "pattern_disposition", "pattern_disposition_description", "pattern_disposition_details",
                            "scenario", "severity", "sha256", "tactic", "tactic_id", "technique",
                            "technique_id", "timestamp", "triggering_process_graph_id", "user_id", "user_name"]:
                behavior_field = log.get(field)
                if isinstance(behavior_field, str):
                    behaviors[field] = behavior_field
            log['behaviors'] = behaviors
        # if entities.agent_ids is present it means we need to enrich log with hosts informations
        # this keeps retro-compatibility by enriching .hosts field for incidents 
        # (that have been removed since the migration from v1 to v2 endpoints)
        elif product == "xdr":
            if ids := log.get('entities', {}).get('agent_ids', []):
                devices = self.get_devices(ids)
                # limit size of hosts array to 100, ensuring low output log size (theorically no more than 65ko - half the rsyslog limit) :
                #   - 50 bytes (max observed field size)
                #   - 13 (max observed fields inside hosts object)
                #   - 100 (hosts limit)
                # => 50*13*100 = 65 000 = 65ko
                log['hosts'] = devices[0:99]

        if parent_cmdline := log.get('parent_details', {}).get('cmdline'):
            log['parent_details']['parent_cmdline'] = parent_cmdline
            del log['parent_details']['cmdline']

        return dumps(log)


    def test(self) -> dict:
        try:
            self.login()

            logger.info(f"[{__parser__}][test]:Running tests...", extra={'frontend': str(self.frontend)})

            since = (timezone.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            to = timezone.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            logs = []
            logs += self.get_logs("detections", since, to)
            if self.request_incidents:
                logs += self.get_logs("incidents", since, to)

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


    def execute(self) -> None:
        self.login()

        kinds = ["detections"]
        if self.request_incidents:
            kinds.append("incidents")

        for kind in kinds:
            # Default timestamp is 7 days ago
            since = self.last_collected_timestamps.get(f"crowdstrike_falcon_{kind}") or self.frontend.last_api_call or (timezone.now() - timedelta(days=7))
            # Get a batch of 24h at most, to avoid running queries for too long
            # also delay the query time of 3 minutes, to avoid missing events
            to = min(timezone.now()-timedelta(minutes=3), since + timedelta(hours=24))

            logs = self.get_logs(kind=kind,
                                 since=since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                 to=to.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
            total = len(logs)

            self.write_to_file([self.format_log(log) for log in logs])
            self.update_lock()

            if total > 0:
                logger.info(f"[{__parser__}][execute]: Total logs fetched : {total}", extra={'frontend': str(self.frontend)})
                self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] = to
            elif not self.last_collected_timestamps.get(f"crowdstrike_falcon_{kind}"):
                # Else if last_collected_timestamps for the requested kind doesn't exists, this happens when :
                # the collector doesn't get logs for the requested period of time at first execution OR last_api_call migration from an existing collection)
                self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] = to
            elif self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] < timezone.now()-timedelta(hours=24):
                # If no logs where retrieved during the last 24hours, move forward 1h to prevent stagnate ad vitam eternam
                self.last_collected_timestamps[f"crowdstrike_falcon_{kind}"] += timedelta(hours=1)

        logger.info(f"[{__parser__}][execute]: Parsing done.", extra={'frontend': str(self.frontend)})
