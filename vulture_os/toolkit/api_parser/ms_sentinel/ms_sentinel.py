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
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Microsoft Sentinel API Parser'
__parser__ = 'MICROSOFT SENTINEL'

# Django system imports
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# Django project imports
from toolkit.api_parser.api_parser import ApiParser

# Extern modules imports
import json
import requests
from datetime import datetime

# Logger import & configuration
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class MSSentinelAPIError(Exception):
    pass


class MSSentinelParser(ApiParser):
    OAUTH_URL = "https://login.microsoftonline.com/{}/oauth2/token"
    API_BASE_URL = "https://management.azure.com"
    INCIDENTS_URI = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents"
    ENTITIES_URI = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/entities"
    API_VERSION = "2021-10-01"

    def __init__(self, data):
        super().__init__(data)

        self.tenant_id = data["ms_sentinel_tenant_id"]
        self.app_id = data["ms_sentinel_appid"]
        self.app_secret = data["ms_sentinel_appsecret"]
        self.subscription_id = data["ms_sentinel_subscription_id"]
        self.resource_group_name = data["ms_sentinel_resource_group"]
        self.workspace_name = data["ms_sentinel_workspace"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                # Retrieve OAuth token (https://docs.microsoft.com/fr-fr/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-nativeapp)
                oauth2_url = self.OAUTH_URL.format(self.tenant_id)
                response = requests.post(
                    oauth2_url,
                    data={
                        'resource' : self.API_BASE_URL,
                        'client_id' : self.app_id,
                        'client_secret' : self.app_secret,
                        'grant_type' : 'client_credentials'
                    },
                    proxies=self.proxies,
                    verify=self.api_parser_verify_ssl
                ).json()

                assert response.get('access_token') is not None, "Cannot retrieve token from API : {}".format(response)

                logger.debug(f"[{__parser__}]:_connect: Authentication succeed - access token retrieved", extra={'frontend': str(self.frontend)})

                self.session.headers.update({'Authorization': "Bearer {}".format(response.get('access_token'))})

            return True

        except Exception as err:
            raise MSSentinelAPIError(err)

    def test(self):
        try:
            status, logs = self.get_incidents(test=True)

            return {
                "status": status,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_incident_entities(self, incident_id):
        self._connect()

        url = self.API_BASE_URL + self.ENTITIES_URI.format(subscriptionId=self.subscription_id,
                                                            resourceGroupName=self.resource_group_name,
                                                            workspaceName=self.workspace_name, incidentId=incident_id)

        params = {
            'api-version': self.API_VERSION
        }

        logger.info(f"[{__parser__}]:get_incident_entities: Get entities request params: {params} , URL : {url}",
                     extra={'frontend': str(self.frontend)})

        response = self.session.post(
            url,
            params=params,
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )
        if response.status_code == 429 and response.headers["Retry-After"]:
            retry_after = int(response.headers["Retry-After"])
            self.evt_stop.wait(retry_after)
            response = self.session.post(
                url,
                params=params,
                proxies=self.proxies,
                verify=self.api_parser_verify_ssl
            )

        if response.status_code != 200:
            logger.error(f"[{__parser__}]:get_incidents: Error at API Call: {response.content}",
                         extra={'frontend': str(self.frontend)})
            return {}

        logger.debug(f"[{__parser__}]:get_incidents: Content retrieved", extra={'frontend': str(self.frontend)})

        return response.json()

    def get_incidents(self, test=False):
        self._connect()

        url = self.API_BASE_URL + self.INCIDENTS_URI.format(subscriptionId=self.subscription_id,
                                                            resourceGroupName=self.resource_group_name,
                                                            workspaceName=self.workspace_name)

        params = {
            'api-version': self.API_VERSION
        }
        if test:
            params['top'] = 10

        logger.info(f"[{__parser__}]:get_incidents: Get incidents request params: {params}, URL : {url}",
                     extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            msg = f"Error at API Call: {response.content}"
            logger.error(f"[{__parser__}]:get_incidents: {msg}", extra={'frontend': str(self.frontend)})
            raise MSSentinelAPIError(msg)

        logger.debug(f"[{__parser__}]:get_incidents: Content retrieved", extra={'frontend': str(self.frontend)})

        return True, response.json()

    def get_incident_alerts(self, incident_url):
        self._connect()

        url = self.API_BASE_URL + incident_url + "/alerts"

        params = {
            'api-version': self.API_VERSION
        }

        logger.info(f"[{__parser__}]:get_incident_alerts: Get incident's alerts request params: {params} , URL : {url}",
                     extra={'frontend': str(self.frontend)})

        response = self.session.post(
            url,
            params=params,
            data="toto",
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )
        if response.status_code == 429 and response.headers["Retry-After"]:
            retry_after = int(response.headers["Retry-After"])
            self.evt_stop.wait(retry_after)
            response = self.session.post(
                url,
                params=params,
                data="toto",
                proxies=self.proxies,
                verify=self.api_parser_verify_ssl
            )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            msg = f"Error at API Call: {response.content}"
            logger.error(f"[{__parser__}]:get_incident_alerts: {msg}", extra={'frontend': str(self.frontend)})
            raise MSSentinelAPIError(msg)

        content = response.json()

        logger.debug(f"[{__parser__}]:get_incident_alerts: Content retrieved : {content}",
                     extra={'frontend': str(self.frontend)})

        return True, content

    def get_incident_comments(self, incident_url):
        self._connect()

        url = self.API_BASE_URL + incident_url + "/comments"

        params = {
            'api-version': self.API_VERSION
        }

        logger.info(f"[{__parser__}]:get_incident_comments: URL : {url} request parameters: {params}",
                     extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=params,
            proxies=self.proxies,
            verify=self.api_parser_verify_ssl
        )
        if response.status_code == 429 and response.headers["Retry-After"]:
            retry_after = int(response.headers["Retry-After"])
            self.evt_stop.wait(retry_after)
            response = self.session.get(
                url,
                params=params,
                proxies=self.proxies,
                verify=self.api_parser_verify_ssl
            )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            msg = f"Error at API Call: {response.content}"
            logger.error(f"[{__parser__}]:get_incident_comments: {msg}", extra={'frontend': str(self.frontend)})
            raise MSSentinelAPIError(msg)

        content = response.json()

        logger.debug(f"[{__parser__}]:get_incident_comments: Content retrieved : {content}",
                     extra={'frontend': str(self.frontend)})
        return True, content

    def parse_alert_time(self, time_str):
        # Reformat correctly to isoformat the timestamp
        ## 2022-04-08T10:15:24.0659763Z      to
        ## 2022-04-08T10:15:24.065976+00:00
        tz = "00:00"
        if "+" in time_str:
            tz = time_str.split("+")[1]
            time_str = time_str.split("+")[0]
        elif "Z" in time_str:
            time_str = time_str.replace("Z", "")
        # Remove too many digits for decimal seconds, if any
        # It is incompatible with isoformat (only 0, 3 or 6 digits allowed)
        if len(time_str) > 23:
            time_str = time_str[:23]
        elif len(time_str) > 20:
            time_str = time_str[:19]
        time_str += "+" + tz
        return datetime.fromisoformat(time_str)

    def outdated_alert(self, alert_time):
        return (alert_time <= self.last_api_call)

    def format_log(self, log):
        if '/' in log.get('id', ""):
            log['url'] = "{}{}".format(self.API_BASE_URL, log['id'])
        return json.dumps(log)

    def execute(self):
        status, result = self.get_incidents()

        if not status:
            raise MSSentinelAPIError(result)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        incidents = result['value']

        if len(incidents) > 0:
            logger.debug(f"[{__parser__}]:execute: {len(incidents)} incidents retrieved", extra={'frontend': str(self.frontend)})

            new_last_api_call = self.last_api_call

            # For each incident, retrieve comments, entities and alerts
            for incident in incidents:

                logs = []

                # Entities
                entities = self.get_incident_entities(incident['name']).get('entities', None)
                if entities:
                    incident['entities'] = entities
                    logger.info(f"[{__parser__}]:execute: {len(entities)} entities founds for incident {incident['name']}",
                                extra={'frontend': str(self.frontend)})
                else:
                    logger.warning(f"[{__parser__}]:execute: Fail to retrieve entities for incident {incident['name']}",
                                extra={'frontend': str(self.frontend)})

                # Comments
                logger.debug(f"[{__parser__}]:execute: {incident['properties']['additionalData']['commentsCount']} "
                             f"comments found for incident {incident['name']}",
                             extra={'frontend': str(self.frontend)})

                if incident['properties']['additionalData']['commentsCount'] > 0:
                    status, result = self.get_incident_comments(incident['id'])
                    if status:
                        comments = result['value']
                        incident['comments'] = comments
                    else:
                        logger.error(f"[{__parser__}]:execute: Fail to retrieve comments for incident {incident['name']}",
                                    extra={'frontend': str(self.frontend)})

                # Alerts
                logger.debug(f"[{__parser__}]:execute: {incident['properties']['additionalData']['alertsCount']} "
                             f"alerts found for incident {incident['name']}",
                             extra={'frontend': str(self.frontend)})

                if incident['properties']['additionalData']['alertsCount'] > 0:
                    status, result = self.get_incident_alerts(incident['id'])
                    if status:
                        alerts = result['value']

                        for alert in alerts:
                            alert_time = self.parse_alert_time(alert['properties']['processingEndTime'])
                            if not self.outdated_alert(alert_time):
                                alert['incident'] = incident
                                logs.append(alert)
                                if alert_time > new_last_api_call:
                                    new_last_api_call = alert_time
                            else:
                                logger.debug(f"[{__parser__}]:execute: Alert {alert['name']} is outdated"
                                             f"({alert_time} < {self.last_api_call})",
                                             extra={'frontend': str(self.frontend)})
                    else:
                        logger.error(f"[{__parser__}]:execute: Fail to retrieve alerts for incident {incident['name']}",
                                     extra={'frontend': str(self.frontend)})

                self.write_to_file([self.format_log(log) for log in logs])
                # Writting & downloading may take some while, so refresh token in Redis
                self.update_lock()

            logger.info(f"[{__parser__}]:execute: Setting last_api_call to {new_last_api_call}",
                         extra={'frontend': str(self.frontend)})

            self.frontend.last_api_call = new_last_api_call
            self.frontend.save(update_fields=["last_api_call"])

        else:
            logger.warning(f"[{__parser__}]:execute: No incident retrieved.", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
