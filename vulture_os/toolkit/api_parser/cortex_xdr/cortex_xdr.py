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
__doc__ = 'Cortex XDR API Parser'
__parser__ = 'CORTEX XDR'

import json
import logging
import requests

from datetime import datetime
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from pytz import utc

from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CortexXDRAPIError(Exception):
    pass


class CortexXDRParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.cortex_xdr_host = data["cortex_xdr_host"]
        self.cortex_xdr_apikey_id = data["cortex_xdr_apikey_id"]
        self.cortex_xdr_apikey = data["cortex_xdr_apikey"]
        self.cortex_xdr_alerts_timestamp = data.get("cortex_xdr_alerts_timestamp")
        self.cortex_xdr_incidents_timestamp = data.get("cortex_xdr_incidents_timestamp")

        self.session = None

        self.event_kinds = {
            "alerts": {
                "url": f"https://api-{self.cortex_xdr_host}/public_api/v2/alerts/get_alerts_multi_events/",
                "time_field": "event_timestamp",
                "default_time_field": "detection_timestamp",
                "filter_by": "server_creation_time"
            },
            "incidents": {
                "url": f"https://api-{self.cortex_xdr_host}/public_api/v1/incidents/get_incidents/",
                "time_field": "modification_time",
                "default_time_field": "detection_timestamp",
                "filter_by": "creation_time"
            }
        }

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.headers.update({'x-xdr-auth-id': str(self.cortex_xdr_apikey_id)})
                self.session.headers.update({'Authorization': str(self.cortex_xdr_apikey)})

            return True

        except Exception as err:
            raise CortexXDRAPIError(err)

    def test(self):
        try:
            status, logs = self.get_logs("incidents", test=True)

            if not status:
                return {
                    "status": False,
                    "error": logs
                }

            return {
                "status": True,
                "data": _('Success')
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, kind, nb_from=0, since=None, test=False):
        self._connect()

        url = self.event_kinds[kind]['url']

        params = {'request_data':
                      {
                          'sort': {
                              'field': self.event_kinds[kind]['filter_by'],
                              'keyword': "asc"
                          },
                          'search_from': nb_from,
                          'search_to': 10 if test else nb_from+100
                      }
        }
        if since:
            params['request_data']['filters'] = [{
                       "field": self.event_kinds[kind]['filter_by'],
                       "operator": "gte",
                       "value": int(since.timestamp()*1000)
                   }]
        msg = f"Get user events request params: {params}"
        logger.debug(f"[{__parser__}]:get_logs: {msg}", extra={'frontend': str(self.frontend)})
        response = self.session.post(
            url,
            json=params,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )

        if response.status_code == 401:
            return False, _('Authentication failed')

        if response.status_code != 200:
            error = f"Error at CortexXDR API Call: {response.content}"
            logger.error(f"[{__parser__}]:get_logs: {error}", extra={'frontend': str(self.frontend)})
            raise CortexXDRAPIError(error)

        content = response.json()

        return True, content

    def execute(self):
        for kind in self.event_kinds.keys():
            logger.info(f"[{__parser__}]:execute: Getting {kind}", extra={'frontend': str(self.frontend)})
            cpt = 0
            total = 1
            while cpt < total:
                status, tmp_logs = self.get_logs(kind, nb_from=cpt, since=getattr(self, f"cortex_xdr_{kind}_timestamp"))

                if not status:
                    raise CortexXDRAPIError(tmp_logs)

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                total = tmp_logs['reply']['total_count']
                cpt += tmp_logs['reply']['result_count'] + 1
                logs = tmp_logs['reply'][kind]

                def format_log(log):
                    log['kind'] = kind

                    log_timestamp = log.get(self.event_kinds[kind]['time_field'], log.get(self.event_kinds[kind]['default_time_field']))
                    if isinstance(log_timestamp, list) and len(log_timestamp) > 0:
                        log_timestamp = log_timestamp[0]

                    log['timestamp'] = datetime.fromtimestamp(log_timestamp/1000, tz=utc).isoformat()

                    # Get first occurence of lists to keep retro-compatibility with actual parser
                    # Actual mapping fields
                    tracking_fields = ['agent_version', 'action_remote_ip', 'action_remote_port', 'dns_query_name', 'event_timestamp', 'module_id', 'host_ip', 'agent_os_sub_type', 'action_file_name', 'action_file_path', 'action_file_md5', 'action_file_sha256', 'event_type', 'action_country', 'action_external_hostname', 'action_process_causality_id', 'action_process_image_command_line', 'action_process_image_name', 'action_process_image_sha256', 'action_process_instance_id', 'action_process_signature_status', 'action_process_signature_vendor', 'actor_causality_id', 'actor_process_causality_id', 'agent_host_boot_time', 'agent_is_vdi', 'association_strength', 'bioc_indicator', 'end_match_attempt_ts', 'event_id', 'story_id', 'action_local_port', 'actor_process_command_line', 'actor_process_image_name', 'actor_process_image_path', 'actor_process_instance_id', 'actor_process_os_pid', 'actor_process_image_md5', 'actor_process_image_sha256', 'actor_process_signature_status', 'actor_process_signature_vendor', 'actor_thread_thread_id', 'causality_actor_causality_id', 'causality_actor_process_command_line', 'causality_actor_process_execution_time', 'causality_actor_process_image_md5', 'causality_actor_process_image_name', 'causality_actor_process_image_path', 'causality_actor_process_image_sha256', 'causality_actor_process_signature_status', 'causality_actor_process_signature_vendor', 'action_registry_data', 'action_registry_key_name', 'action_registry_value_name', 'action_local_ip', 'mitre_tactic_id_and_name', 'mitre_technique_id_and_name']
                    list_fields = set()
                    for k, v in log.items():
                        if k in tracking_fields and isinstance(v, list):
                            if len(v) == 0:
                                log[k] = None
                            else:
                                if len(v) > 1:
                                    list_fields.add(k)
                                    logger.error(f"[{__parser__}]:format_log: WARNING: field '{k}' has more than one occurrence. The first is keeped, the others will be ignored.",
                                             extra={'frontend': str(self.frontend)})
                                log[k] = v[0]
                    log["list_fields"] = list(list_fields)

                    return json.dumps(log)

                self.write_to_file([format_log(log) for log in logs])
                # Writting may take some while, so refresh token in Redis
                self.update_lock()

                if len(logs) > 0:
                    # Replace "Z" by "+00:00" for datetime parsing
                    # No need to make_aware, date already contains timezone
                    # add 1 (ms) to timestamp to avoid getting last alert again
                    try:
                        setattr(self.frontend, f"cortex_xdr_{kind}_timestamp", datetime.fromtimestamp((logs[-1][self.event_kinds[kind]['time_field']]+1)/1000, tz=utc))
                    except Exception:
                        msg = f"Could not locate key '{self.event_kinds[kind]['time_field']}' from following log: {logs[-1]}"
                        logger.error(f"[{__parser__}]:execute: {msg}",
                                     extra={'frontend': str(self.frontend)})

        logger.info("CortexXDR parser ending.", extra={'frontend': str(self.frontend)})
