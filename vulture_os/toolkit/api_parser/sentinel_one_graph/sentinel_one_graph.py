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
__author__ = "Mael Bonniot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Sentinel One Graph Collector'
__parser__ = 'SENTINEL_ONE_GRAPH'

import logging
from datetime import timedelta, datetime
from json import JSONDecodeError, dumps
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError, ReadTimeout
from requests import Session

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SentinelOneGraphError(Exception):
    pass


class SentinelOneGraphParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.sentinel_one_graph_token = data["sentinel_one_graph_token"]

        self.sentinel_one_graph_console_url = "https://" + self.data["sentinel_one_graph_console_url"].split("://")[-1].rstrip("/")
        self.UNIFIED_ALERTS = '/web/api/v2.1/unifiedalerts/graphql'
        self.url = f"{self.sentinel_one_graph_console_url}{self.UNIFIED_ALERTS}"

        self.session = Session()


    def login(self):
        self.session.headers.update({"Authorization": f"Bearer {self.sentinel_one_graph_token}"})
        return


    def execute_query(self, url: str, data: dict, timeout: int = 10) -> dict:
        retry = 0
        resp_json = dict()

        while retry < 3 and not self.evt_stop.is_set():
            retry += 1
            try:
                logger.info(f"[{__parser__}][execute_query]: Querying url {url} - retry {retry}/3", extra={'frontend': str(self.frontend)})

                response = self.session.post(
                    url=url,
                    json=data,
                    timeout=timeout,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)

                response.raise_for_status()
                resp_json = response.json()
                break

            except (HTTPError, ConnectionError) as e:
                logger.error(f"[{__parser__}][execute_query]: HTTPError raised -- {e}", extra={'frontend': str(self.frontend)})
                continue
            except JSONDecodeError as e:
                logger.error(f"[{__parser__}][execute_query]: Impossible to decode json response -- {e}", extra={'frontend': str(self.frontend)})
                continue
            except (TimeoutError, ReadTimeout, ConnectTimeout) as e:
                logger.warning(f"[{__parser__}][execute_query]: TimeoutError we will retry a request soon -- {e}", extra={'frontend': str(self.frontend)})
                continue

        if retry == 3:
            raise SentinelOneGraphError("Failed to fetch logs after 3 tries")

        return resp_json


    def get_itdr_alert_ids(self, since: int, to: int, limit: int = 50) -> list:
        query = """
            fragment PageInfo on PageInfo {endCursor hasNextPage}
            query GetAlerts($first:Int, $after:String, $filters:[FilterInput!]) {
                alerts(first:$first after:$after filters:$filters) {
                    totalCount
                    pageInfo {...PageInfo}
                    edges {
                        cursor
                        node {
                            id
                        }
                    }
                }
            }
        """

        logger.info(f"[{__parser__}][get_itdr_alert_ids]: Getting available alert IDs, from {since} to {to}", extra={'frontend': str(self.frontend)})

        variables  = {
            'first': limit, # This is the limit of items returned for one query - not the entire gathering, as we paginate below
            'filters' : [
                {
                    'fieldId': 'detectedAt',
                    'dateTimeRange': {
                        'start': since,
                        'startInclusive': True,
                        'end': to,
                        'endInclusive': False
                    }
                }
            ],
            'sort': {'by': 'detectedAt', 'order': 'ASC'},
        }

        edges = []
        ret = []

        response = self.execute_query(
            self.url,
            data={'query': query, 'variables': variables})

        alerts: dict = response.get('data', {}).get('alerts', {})
        edges.extend(alerts.get('edges', []))

        while alerts.get('pageInfo', {}).get('hasNextPage', False) and not self.evt_stop.is_set():
            variables['after'] = alerts.get('pageInfo', {}).get('endCursor', '')

            response = self.execute_query(
                self.url,
                data={'query': query, 'variables': variables})

            alerts = response.get('data', {}).get('alerts', {})
            edges.extend(alerts.get('edges', []))

        ret = [edge.get('node', {}).get('id') for edge in edges if edge]

        return ret


    def get_itdr_alert_details(self, event_id: str) -> dict:
        query = """
            fragment Account on Account {id name}
            fragment Analytics on Analytics {category name typeValue}
            fragment Asset on Asset {agentUuid agentVersion category connectivityToConsole id lastLoggedInUser name osType osVersion pendingReboot policy subcategory type}
            fragment Assignee on User {email fullName}
            fragment Attacker on DetectionAttackerDetails {host ip}
            fragment Cloud on DetectionCloud {accountId cloudProvider image instanceId instanceSize location network tags}
            fragment File on FileDetail {certExpiresAt certSerialNumber certSubject md5 name path sha1 sha256 size}
            fragment Group on Group {id name}
            fragment Kubernetes on DetectionKubernetes {clusterName containerId containerImageName containerLabels containerName containerNetworkStatus controllerLabels controllerName controllerType namespaceLabels namespaceName nodeLabels nodeName podLabels podName}
            fragment Observables on Observable {name type value}
            fragment Site on Site {id name}
            fragment DetectionSource on DetectionSource {engine product}
            fragment Tactic on Tactic {name uid}
            fragment TargetUser on DetectionTargetUserDetails {domain name}
            fragment Technique on Technique {name uid}
            fragment Attacks on Attack {tactic {...Tactic} technique {...Technique}}
            fragment Process on ProcessDetail {cmdLine file {...File} parentName username}
            fragment Scope on Scope {account {...Account} group {...Group} site {...Site}}
            fragment DetectionTime on DetectionTime {attacker {...Attacker} cloud {...Cloud} kubernetes {...Kubernetes} targetUser {...TargetUser} asset {...DetectionAsset}}
            fragment Indicators on Indicator {attacks {...Attacks} eventTime message observables {...Observables} severity type}
            fragment RealTime on RealTime {scope {...Scope}}
            fragment DetectionAsset on DetectionAsset {ipV4 ipV6 domain consoleIpAddress}
            query GetAlert($id:ID!) {
                alert(id:$id) {
                    analystVerdict
                    analytics {...Analytics}
                    asset {...Asset}
                    assignee {...Assignee}
                    attackSurfaces
                    classification
                    confidenceLevel
                    createdAt
                    description
                    detectedAt
                    detectionSource {...DetectionSource}
                    detectionTime {...DetectionTime}
                    externalId
                    fileHash
                    fileName
                    firstSeenAt
                    id
                    indicators {...Indicators}
                    lastSeenAt
                    name
                    noteExists
                    process {...Process}
                    realTime {...RealTime}
                    result
                    severity
                    status
                    storylineId
                    updatedAt
                    rawData
                }
            }
        """
        logger.info(f"[{__parser__}][get_itdr_alert_details]: Getting alert details for alert {event_id}", extra={'frontend': str(self.frontend)})

        response = self.execute_query(
            self.url,
            data={'query': query, 'variables': {'id': event_id}}
        )

        log = response.get('data', {}).get('alert', {})

        # Comments
        if log and log.get('noteExists'):
            comments = []
            if log_id := log.get("id"):
                for comment in self.get_itdr_alert_comments(log_id):
                    name = comment.get('author', {}).get('fullName', "")
                    email = comment.get('author', {}).get('email', "")
                    if (date := comment.get('createdAt')) and isinstance(date, str):
                        date = date.replace('Z', '+00:00')
                    comments.append({
                        'id': comment['id'],
                        'message': comment['text'],
                        'username': f"{name} ({email})",
                        'timestamp': datetime.fromisoformat(date).isoformat()
                    })
            log['comments'] = comments

        return log


    def get_itdr_alert_comments(self, event_id: str) -> list:
        query = """
        fragment User on User {email fullName}
            query GetAlertnotes($alertId:ID!) {
                alertNotes(alertId:$alertId) {
                    data {id text createdAt updatedAt author {...User}
                }
            }
        }
        """
        logger.info(f"[{__parser__}][get_itdr_alert_comments]: Getting alert comments for alert {event_id}", extra={'frontend': str(self.frontend)})

        response = self.execute_query(
            self.url,
            data={'query': query, 'variables': {'alertId': event_id}}
        )

        return response.get('data', {}).get('alertNotes', {}).get('data', [])


    def format_log(self, log: dict) -> str:
        # Observer name
        log["observer_name"] = self.sentinel_one_graph_console_url

        # Mitre tactics/techniques
        tactics = list()
        techniques = list()

        for indicator in log.get("indicators", []):
            attacks = indicator.get("attacks")
            if isinstance(attacks, list):
                for attack in attacks:
                    tactics.append(attack.get("tactic"))
                    techniques.append(attack.get("technique"))

        log["mitre_technique_ids"] = list(set([x.get("uid") for x in techniques if x is not None]))
        log["mitre_technique_names"] = list(set([x.get("name") for x in techniques if x is not None]))

        log["mitre_tactic_ids"] = list(set([x.get("uid") for x in tactics if x is not None]))
        log["mitre_tactic_names"] = list(set([x.get("name") for x in tactics if x is not None]))

        # needs_attention
        resolved = log.get('resolved')
        status = log.get('status')
        if status and resolved:
            log['needs_attention'] = str(status).lower() not in resolved

        # createdAt
        if (createdAt := log.get('createdAt')) and isinstance(createdAt, str):
            log['createdAt'] = datetime.fromisoformat(createdAt.replace('Z', '+00:00')).isoformat()

        # process_args
        process = log.get("process")
        if isinstance(process, dict):
            process_cmdline = process.get("cmdLine")
            if isinstance(process_cmdline, str):
                process_path = process.get("path", "")
                process_deduces_args = process_cmdline.replace(process_path, "")
                log["process_args"] = process_deduces_args.split(" ")

        # is_blocked
        result = log.get('result')
        if isinstance(result,str):
            log['is_blocked'] = result.lower() not in ['unmitigated', 'benign']

        # is_kubernetes
        log['is_kubernetes'] = False
        if kubernetes := log.get('detectionTime', {}).get('kubernetes', {}):
            log['is_kubernetes'] = any(kubernetes.values())

        # is_cloud
        log['is_cloud'] = False
        if cloud := log.get('detectionTime', {}).get('cloud', {}):
            if cloud.get('cloudProvider'):
                log["is_cloud"] = True

        # rawData interesting fields selection (to avoid as much as possible log expansion)
        evidences = log["rawData"].get('evidences')
        if isinstance(evidences, list):
            if len(evidences) > 0:
                log["process_file_extension"] = evidences[0].get('process', {}).get('file', {}).get('mime_type', "")
                log["process_file_signature_signature"] = evidences[0].get('process', {}).get('file', {}).get('signature', {}).get('algorithm', "")
        del log["rawData"]

        return dumps(log)


    def test(self):
        logs = []

        try:
            self.login()

            since = timezone.now() - timedelta(days=1)
            to = timezone.now()

            alert_ids = self.get_itdr_alert_ids(
                since=int(since.timestamp()*1000),
                to=int(to.timestamp()*1000),
                limit=100)

            for id in alert_ids:
                logs.append(self.format_log(self.get_itdr_alert_details(id)))

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            return {
                "status": False,
                "error": str(e)
            }


    def execute(self):
        self.login()

        current_time = timezone.now()
        logs = list()

        since = self.last_api_call or (current_time - timedelta(days=7))
        to = min(since + timedelta(hours=24), current_time - timedelta(minutes=3))

        logger.info(f"[{__parser__}][execute]: Parser starting from {since} to {to}", extra={'frontend': str(self.frontend)})

        alert_ids = self.get_itdr_alert_ids(
            since=int(since.timestamp()*1000),
            to=int(to.timestamp()*1000),
            limit=100
        )

        logger.info(f"[{__parser__}][execute]: {len(alert_ids)} alerts to get...", extra={'frontend': str(self.frontend)})

        for id in alert_ids:
            logger.debug(f"[{__parser__}][execute]: Getting alert '{id}'", extra={'frontend': str(self.frontend)})
            event_detail = self.get_itdr_alert_details(id)
            detectionProduct = event_detail.get('detectionSource', {}).get('product', "")

            # filters out interesting log's type (Identity (itdr) and ['EDR', 'CWS', 'STAR'] (edr))
            # as API have trouble to deal with nested objects
            if isinstance(detectionProduct, str) and detectionProduct in ["Identity", 
                                                                          "EDR", "CWS", "STAR"]:
                logs.append(self.format_log(event_detail))

            if self.evt_stop.is_set():
                break

        # this condition is ugly but permit to not refacto the entire collector now because we are short of time
        # it is there to avoid writing logs / save timestamp in case we are stopping the collector
        # it MAY NOT have a important incidence, as observed volumetry is around 1log/day, thus it's not so costly to redo log gathering operations
        # on collector restart and SHOULD have a limited impact
        if not self.evt_stop.is_set():
            if len(alert_ids) > 0: # if logs
                logger.info(f"[{__parser__}][execute]: Succesfully got {len(alert_ids)} alerts", extra={'frontend': str(self.frontend)})
                self.write_to_file(logs)
                self.frontend.last_api_call = to
                self.frontend.save(update_fields=["last_api_call"])
                logger.info(f"[{__parser__}]:execute: Updated last_api_call -- {self.frontend.last_api_call}", extra={'frontend': str(self.frontend)})
            elif (since < (current_time - timedelta(hours=24))): # or timestamp to old
                self.frontend.last_api_call += timedelta(hours=1)
                self.frontend.save(update_fields=["last_api_call"])
                logger.info(f"[{__parser__}]:execute: Updated last_api_call -- {self.frontend.last_api_call}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
