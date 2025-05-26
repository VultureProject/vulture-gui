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
__author__ = "Theo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Proofpoint TAP SIEM API'
__parser__ = 'PROOFPOINT'

import logging
from datetime import datetime, timedelta
from json import JSONDecodeError, dumps
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError, ReadTimeout
from requests import Session

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SentinelOneIdentityGraphError(Exception):
    pass


class SentinelOneIdentityGraphParser(ApiParser):
    def __init__(self, data):
        self.sentinel_one_identity_graph_token = data["sentinel_one_identity_graph_token"]

        self.sentinel_one_identity_graph_console_url = data["sentinel_one_identity_graph_console_url"]

        self.path_url = 'web/api/v2.1/unifiedalerts/graphql'
        self.url = self.sentinel_one_identity_graph_console_url + self.path_url

        self.session = Session()

    def login(self):
        self.session.headers.update({"Authorization": f"Bearer {self.sentinel_one_identity_graph_token}"})
        return

    def execute_query(self, url: str, data: dict, timeout: int = 10):
        retry = 3

        while retry > 0:
            try:
                response = self.session.post(
                    url=url,
                    json=data,
                    timeout=timeout)
                resp_json = response.json()

            except (HTTPError, ConnectionError) as e:
                logger.exception(f"[{__parser__}][execute_query]: HTTPError raised -- {url} - {data} -- {response.content}", extra={'frontend': str(self.frontend)})
                raise e
            except JSONDecodeError as e:
                logger.exception(f"[{__parser__}][execute_query]: Impossible to decode json response -- {response.content}", extra={'frontend': str(self.frontend)})
                retry -= 1
                continue
            except (TimeoutError, ReadTimeout, ConnectTimeout) as e:
                logger.exception(f"[{__parser__}][execute_query]: TimeoutError we will retry a request soon -- retry {retry}/3 -- {response.content}", extra={'frontend': str(self.frontend)})
                retry -= 1
                continue
            break

        return resp_json

    def get_itdr_events_ids(self, since: int, to: int, limit: int = 50):
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

        variables  = {
            'first': limit, # This is the limit of API returns for one query
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
                # {'fieldId': 'detectionProduct', 'stringIn': {'values': ['Identity']}} # Could be ignorded, this way of API will be used for EDR as well
                # -> this tends to weird API bugs in combination of detectedAt
            ]
        }

        edges = []
        ret = []

        response = self.execute_query(
            self.url,
            data={'query': query, 'variables': variables})

        alerts = response.get('data', {}).get('alerts', {})
        edges.extend(alerts.get('edges', []))

        while alerts.get('pageInfo', {}).get('hasNextPage', False):
            variables['after'] = alerts.get('pageInfo', {}).get('endCursor', '')

            response = self.execute_query(
                self.url,
                data={'query': query, 'variables': variables})

            alerts = response.get('data', {}).get('alerts', {})
            edges.extend(alerts.get('edges', []))

        ret = [edge.get('node', {}).get('id') for edge in edges if edge]

        return ret


    def get_itdr_event_details(self, event_id: str):
        query = """
            fragment Account on Account {name}
            fragment Analytics on Analytics {category name type}
            fragment Asset on Asset {agentUuid agentVersion category connectivityToConsole id lastLoggedInUser name osType osVersion pendingReboot policy subcategory type}
            fragment Assignee on User {email fullName}
            fragment Attacker on DetectionAttackerDetails {host ip}
            fragment Cloud on DetectionCloud {accountId cloudProvider image instanceId instanceSize location network tags}
            fragment File on FileDetail {certExpiresAt certSerialNumber certSubject md5 name path sha1 sha256 size}
            fragment Group on Group {name}
            fragment Kubernetes on DetectionKubernetes {clusterName containerId containerImageName containerLabels containerName containerNetworkStatus controllerLabels controllerName controllerType namespaceLabels namespaceName nodeLabels nodeName podLabels podName}
            fragment Observables on Observable {name type value}
            fragment Site on Site {name}
            fragment DetectionSource on DetectionSource {engine product}
            fragment Tactic on Tactic {name uid}
            fragment TargetUser on DetectionTargetUserDetails {domain name}
            fragment Technique on Technique {name uid}
            fragment Attacks on Attack {tactic {...Tactic} technique {...Technique}}
            fragment Process on ProcessDetail {cmdLine file {...File} parentName username}
            fragment Scope on Scope {account {...Account} group {...Group} site {...Site}}
            fragment DetectionTime on DetectionTime {attacker {...Attacker} cloud {...Cloud} kubernetes {...Kubernetes} targetUser {...TargetUser}}
            fragment Indicators on Indicator {attacks {...Attacks} eventTime message observables {...Observables} severity type}
            fragment RealTime on RealTime {scope {...Scope}}
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
                }
            }
        """

        response = self.execute_query(
            self.url,
            data={'query': query, 'variables': {'id': event_id}}
        )

        return response.get('data', {}).get('alert', {})

    def format_log(self, log: dict) -> str:
        return dumps(log)

    def test(self):
        logs = []

        try:
            since = timezone.now() - timedelta(days=1)
            to = timezone.now()

            alert_ids = self.get_itdr_events_ids(
                since=int(since.timestamp()*1000),
                to=int(to.timestamp()*1000),
                limit=100)

            for id in alert_ids:
                logs.append(self.get_itdr_event_details(id))

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
        kind = "sentinel_one_identity_graph_alerts"

        current_time = timezone.now()

        since = datetime.strptime(self.last_collected_timestamps.get(kind), "%Y-%m-%dT%H:%M:%SZ") or current_time - timedelta(days=7)
        to = min(since + timedelta(days=1), current_time - timedelta(minutes=3))

        while to < current_time - timedelta(minutes=3):
            since = datetime.strptime(self.last_collected_timestamps.get(kind), "%Y-%m-%dT%H:%M:%SZ") or timezone.now() - timedelta(days=7)
            to = min(since + timedelta(days=1), current_time - timedelta(minutes=3))

            alert_ids = self.get_itdr_events_ids(
                since=int(since.timestamp()*1000),
                to=int(to.timestamp()*1000),
                limit=100
            )

            logger.info(f"[{__parser__}][execute]: Successfully gets {len(alert_ids)} alert's ids", extra={'frontend': str(self.frontend)})

            for id in alert_ids:
                event_detail = self.get_itdr_event_details(id)
                self.write_to_file(event_detail)

            if len(alert_ids) > 0 or since < current_time - timedelta(hours=24): # if logs or timestamp to old
                self.last_collected_timestamps[kind] = datetime.strftime(to, "%Y-%m-%dT%H:%M:%SZ")
