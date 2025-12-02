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
__author__ = "Julien Pollet"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Proofpoint TRAP API'
__parser__ = 'PROOFPOINT TRAP'


# Django system imports
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from djongo import models

# Django project imports
from api_collector.models.base import ApiCollector
from toolkit.api_parser.api_parser import ApiParser

# Extern modules imports
from datetime import timedelta
import json
import requests

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ProofpointTRAPAPIError(Exception):
    pass


class ProofpointTRAPAPIRateLimitError(Exception):
    pass


class ProofpointTRAPCollector(ApiCollector):
    # Proofpoint TRAP attributes
    host = models.TextField(
        verbose_name = _("ProofPoint TRAP host"),
        help_text = _("ProofPoint API root url"),
        default = "",
    )
    apikey = models.TextField(
        verbose_name = _("ProofPoint TRAP API key"),
        help_text = _("ProofPoint TRAP API key"),
        default = "",
    )


class ProofpointTRAPParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.proofpoint_trap_host = data["proofpoint_trap_host"]
        if not self.proofpoint_trap_host.startswith('https://') and not self.proofpoint_trap_host.startswith('http://'):
            self.proofpoint_trap_host = "https://" + self.proofpoint_trap_host

        self.proofpoint_trap_apikey = data["proofpoint_trap_apikey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                headers.update({'Authorization': self.proofpoint_trap_apikey})

                self.session.headers.update(headers)

            return True

        except Exception as err:
            raise ProofpointTRAPAPIError(err)

    def __execute_query(self, url, query=None, timeout=20):

        self._connect()

        msg = "URL : " + url + " Query : " + str(query)
        logger.info(f"[{__parser__}] Request API : {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=query,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl
        )

        # handler rate limit exceeding
        if response.status_code == 429:
            raise ProofpointTRAPAPIRateLimitError
        elif response.status_code != 200:
            raise ProofpointTRAPAPIError(
                f"Error at Proofpoint TRAP API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def test(self):

        current_time = timezone.now()
        try:
            since = current_time - timedelta(hours=4)
            to = current_time
            logs, _ = self.get_logs(since=since, to=to)

            return {
                "status": True,
                "data": logs
            }
        except Exception as e:
            logger.exception(f"{[__parser__]}:test: {str(e)}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since, to):
        alert_url = self.proofpoint_trap_host + "/api/incidents"

        while not self.evt_stop.is_set():

            # Format timestamp for query
            since_formatted = since.isoformat()[:19] + 'Z'
            to_formatted = to.isoformat()[:19] + 'Z'

            query = {
                'created_after': since_formatted,  # >= created_at
                'created_before': to_formatted,  # < created_at
            }

            try:
                return self.__execute_query(alert_url, query), to
            except requests.exceptions.ReadTimeout:
                to = to - (to-since)/2
                assert (to-since) > timedelta(minutes=1), "Reduced range is too small, cannot continue"
                logger.warning(f"[{__parser__}]:get_logs: Read Timeout: decreasing time range: {since} -> {to}",
                            extra={'frontend': str(self.frontend)})
                self.update_lock()
                continue
            except ProofpointTRAPAPIRateLimitError:
                logger.info(f"[{__parser__}]:execute: API Rate limit exceeded, waiting 10 seconds...",
                    extra={'frontend': str(self.frontend)})
                self.evt_stop.wait(10)

        return None, None

    def format_incidents_logs(self, incident_log):

        incident_details = {}

        for item in incident_log["incident_field_values"]:
            key_name = item["name"].replace(" ", "_").lower()
            incident_details[key_name] = item["value"]

        for alert in incident_log['events']:
            alert['incidentId'] = incident_log['id']
            alert['users'] = incident_log['users']
            alert['score'] = incident_log['score']
            alert['hosts'] = incident_log['hosts']
            alert['domain'] = self.proofpoint_trap_host
            alert['incident_details'] = incident_details

        return incident_log

    def format_alerts_logs(self, alert_log):

        for email in alert_log.get('emails', []):
            # Choose the right email
            if email['recipient']['email'].startswith('trapclear'):
                continue

            original_email = email
            tmp_header = {}

            if 'headers' in original_email:
                # Keep useful Headers
                if "Authentication-Results-Original" in original_email['headers']:
                    tmp_header["Authentication-Results"] = original_email['headers']["Authentication-Results-Original"]

                elif "Authentication-Results" in original_email['headers']:
                    tmp_header["Authentication-Results"] = original_email['headers']["Authentication-Results"]

                if "Return-Path" in original_email['headers']:
                    tmp_header["Return-Path"] = original_email['headers']["Return-Path"]

            original_email['headers'] = tmp_header

            # Drop useless parts
            original_email['body'] = ""
            original_email['mimeContent'] = ""
            original_email['urls'] = ""

            # Save the chosen email in new field 'email'
            alert_log['email'] = original_email

        alert_log['emails'] = ""

        return json.dumps(alert_log)

    def execute(self):

        since = self.frontend.last_api_call or (timezone.now() - timedelta(days=30))

        # fetch at most 24h of logs to avoid the process running for too long
        to = min(timezone.now(), since + timedelta(hours=24))

        # delay the times of 15 minutes, to get the "updated" event
        to = to - timedelta(minutes=15)
        if since > to:
            since = to - timedelta(minutes=1)

        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        response, to = self.get_logs(since, to)

        # Downloading may take some while, so refresh token in Redis
        self.update_lock()

        if response:
            logger.info(f"[{__parser__}]: GET LOG OK", extra={'frontend': str(self.frontend)})

            for incident_log in response:
                formated_incident_log = self.format_incidents_logs(incident_log)
                alert_logs = formated_incident_log['events']

                self.write_to_file([self.format_alerts_logs(log) for log in alert_logs])

                # Writting may take some while, so refresh token in Redis
                self.update_lock()

            # update last_api_call only if logs are retrieved
            self.frontend.last_api_call = to
            self.frontend.save(update_fields=["last_api_call"])
        elif since < timezone.now() - timedelta(hours=24):
            self.frontend.last_api_call = since + timedelta(hours=1)
            self.frontend.save(update_fields=["last_api_call"])

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
