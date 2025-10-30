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
__author__ = "Robin Langlois"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'CNAPP WIZ API Parser'
__parser__ = 'CNAPP WIZ'


from datetime import timedelta, datetime
import json
import logging
import requests

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CnappWizAPIError(Exception):
    pass


class CnappWizParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.cnapp_wiz_client_id = data.get('cnapp_wiz_client_id')
        self.cnapp_wiz_client_secret = data.get('cnapp_wiz_client_secret')
        self.auth_url = "https://auth.app.wiz.io/oauth/token"
        self.api_url = "https://api.eu15.app.wiz.io/graphql"

        self.access_token = None
        self.access_expires_at = None
        if self.frontend and self.frontend.cnapp_wiz_access_token and self.frontend.cnapp_wiz_access_expires_at:
            logger.info(f"[{__parser__}]:__init__: Loading cached token", extra={'frontend': str(self.frontend)})
            self.access_token = self.frontend.cnapp_wiz_access_token
            self.access_expires_at = self.frontend.cnapp_wiz_access_expires_at


    def __connect(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        data = {
            "grant_type": "client_credentials",
            "audience": "wiz-api",
            "client_id": self.cnapp_wiz_client_id,
            "client_secret": self.cnapp_wiz_client_secret,
        }

        logger.info(f"[{__parser__}]:__connect: Fetching a new token", extra={'frontend': str(self.frontend)})

        try:
            response = requests.post(self.auth_url,
                                     data=data,
                                     headers=headers,
                                     proxies=self.proxies,
                                     verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)

            response.raise_for_status()

            self.access_token = response.json()['access_token']
            self.access_expires_at = datetime.now() + timedelta(seconds=int(response.json()['expires_in']))
            if self.frontend:
                self.frontend.cnapp_wiz_access_token = self.access_token
                self.frontend.cnapp_wiz_access_expires_at = self.access_expires_at
                self.frontend.save(update_fields=["cnapp_wiz_access_token", "cnapp_wiz_access_expires_at"])
        except requests.HTTPError as e:
            logger.error(f"[{__parser__}]:__connect: HTTP Error while trying to get a new token: {e}",
                         extra={'frontend': str(self.frontend)})
            if e.response and e.response.content:
                logger.info(
                    f"[{__parser__}]:__connect: Status: {e.response.status_code}, Content: {e.response.content}",
                    extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not retrieve token, HTTP error")
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"[{__parser__}]:__connect: Network error while trying to get a new token: {e}",
                         extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not retrieve token, network error")
        except KeyError as e:
            logger.error(f"[{__parser__}]:__connect: error while accessing token information in response: {e}",
                         extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not fetch logs, key access error")
        except Exception as e:
            logger.error(f"[{__parser__}]:__connect: Error while trying to get a new token: {e}",
                         extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not retrieve token, unknown error")


    def __execute_query(self, since, to, limit):
        logger.info(f"[{__parser__}]:__execute_query: Sending query with params since={since}, to={to}, limit={limit}",
                    extra={'frontend': str(self.frontend)})
        issue_list = []

        # this is the graphql query string, we need double-brackets in order to format some variables inside the query
        graphql_query = f"""
                            query GetIssuesQuery {{
                              issuesV2(
                                first: {limit}
                                after: null
                                orderBy: {{ direction: ASC, field: CREATED_AT }}
                                filterBy: {{
                                  createdAt: {{
                                    before: "{to.isoformat()}"
                                    after: "{since.isoformat()}"
                                  }}
                                  type: [THREAT_DETECTION]
                                  status: [OPEN, IN_PROGRESS]
                                  severity: [CRITICAL, HIGH, MEDIUM, LOW]
                                }}
                              ) {{
                                totalCount
                                pageInfo {{
                                  endCursor
                                  hasNextPage
                                }}
                                nodes {{
                                  id
                                  remediationStrategies{{
                                    id
                                  }}
                                  aiClassification {{
                                    scenario
                                    description
                                  }}
                                  commentThread {{
                                    id
                                  }}
                                  resolvedAt
                                  reopenedAt
                                  resolutionReason

                                  resolutionEvidence {{
                                    id

                                  }}
                                  projects {{
                                    id

                                  }}
                                  cloudAccounts {{
                                    id

                                  }}
                                  cloudOrganizations {{
                                    id
                                  }}
                                  evidenceQuery
                                  entitySnapshot {{
                                    id
                                    cloudPlatform
                                    region
                                  }}
                                  resolvedBy{{
                                    user {{
                                      id
                                    }}
                                  }}
                                  serviceTickets {{
                                    id
                                  }}
                                  resolutionNote
                                  openReason
                                  dueAt
                                  rejectionExpiredAt
                                  statusChangedAt
                                  suggestions
                                  threatDetectionDetails {{
                                    id
                                  }}
                                  applicationServices {{
                                    id
                                  }}
                                  environments
                                  url
                                  groupingType
                                  applicationServiceIssueDetails {{
                                    issuesTotalCount
                                  }}
                                  threatCenterActors {{
                                    id

                                  }}
                                  responseActions {{
                                    edges {{
                                      node {{
                                        id
                                      }}
                                    }}
                                  }}

                                  assignee {{
                                    id
                                  }}
                                  sourceRules {{
                                    id
                                    securitySubCategories {{
                                        category {{
                                            framework {{
                                                name
                                            }}
                                            name
                                        }}
                                        title
                                    }}
                                  }}
                                  status
                                  type
                                  severity
                                  createdAt
                                  updatedAt
                                  description
                                  entity {{
                                    id
                                    name
                                    type
                                    lastSeen
                                  }},
                                }}
                              }}
                            }}
                        """

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        query = {
            "query": graphql_query
        }

        try:
            response = requests.post(self.api_url,
                                     headers=headers,
                                     json=query,
                                     proxies=self.proxies,
                                     verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)
            response.raise_for_status()

            data = response.json()

            for issue in data["data"]["issuesV2"]["nodes"]:
                issue_list.append(issue)

            return issue_list
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"[{__parser__}]:__execute_query: Network Error while executing query: {e}",
                         extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not fetch logs, network error")
        except requests.HTTPError as e:
            logger.error(f"[{__parser__}]:__execute_query: HTTP Error while executing query: {e}",
                         extra={'frontend': str(self.frontend)})
            if e.response and e.response.content:
                logger.info(
                    f"[{__parser__}]:__execute_query: Status: {e.response.status_code}, Content: {e.response.content}",
                    extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not fetch logs, HTTP error")
        except KeyError as e:
            logger.error(f"[{__parser__}]:__execute_query: error while accessing issues in response: {e}",
                         extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not fetch logs, key access error")
        except json.JSONDecodeError as e:
            logger.error(f"[{__parser__}]:__execute_query: error while decoding json result: {e}",
                         extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not fetch logs, JSON decoding error")
        except Exception as e:
            logger.error(f"[{__parser__}]:__execute_query: unknown error {e}", extra={'frontend': str(self.frontend)})
            raise CnappWizAPIError("Could not fetch logs, unknown error")


    def _get_logs(self, since, to, limit=100):
        if not self.access_token or not self.access_expires_at or (self.access_expires_at <= (timezone.now() + timedelta(minutes=1))):
            logger.info(f"[{__parser__}]:_get_logs: No valid token found", extra={'frontend': str(self.frontend)})
            self.__connect()

        return self.__execute_query(since, to, limit)


    def test(self):
        try:
            since = (timezone.now() - timedelta(days=90))
            to = timezone.now()
            data = self._get_logs(since, to, limit=10)
            return {
                'status': True,
                'data': data
            }
        except CnappWizAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }


    def format_log(self, log):
        return json.dumps(log)


    def execute(self):
        since = self.last_api_call or (timezone.now() - timedelta(days=7))
        to = min(timezone.now(), since + timedelta(hours=24))

        try:
            logger.info(f"[{__parser__}]:execute: Querying logs from {since} to {to}",
                        extra={'frontend': str(self.frontend)})
            logs = self._get_logs(since, to)
            self.update_lock()

            if len(logs) > 0:
                self.write_to_file([self.format_log(log) for log in logs])
                last_timestamp = datetime.fromisoformat(logs[-1]['createdAt'])
                # avoid duplicate logs
                last_timestamp = last_timestamp + timedelta(milliseconds=1)
                logger.info(f"[{__parser__}]:execute: Received data, update timestamp to {last_timestamp}", extra={'frontend': str(self.frontend)})

                self.frontend.last_api_call = last_timestamp
            elif since < timezone.now() - timedelta(hours=24):
                # If no logs where retrieved during the last 24hours,
                # move forward 1h to prevent stagnate ad vitam eternam
                logger.info(f"[{__parser__}]:execute: No data retrieved for past 24h, updating timestamp "
                            f"to {since + timedelta(hours=1)}",
                            extra={'frontend': str(self.frontend)})
                self.frontend.last_api_call = since + timedelta(hours=1)

            self.frontend.save(update_fields=["last_api_call"])

        except Exception as e:
            raise CnappWizAPIError(e)

