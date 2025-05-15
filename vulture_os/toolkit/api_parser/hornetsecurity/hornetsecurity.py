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

__author__ = "mbonniot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Hornet Security API Parser toolkit'
__parser__ = 'HORNETSECURITY'


from requests import get, post
from datetime import datetime, timedelta
from json import dumps, loads, JSONDecodeError
from base64 import b64encode
from requests.exceptions import HTTPError

import logging
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class HornetSecurityAPIError(Exception):
    pass


class HornetSecurityParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.hornetsecurity_app_id = data["hornetsecurity_app_id"]
        self.hornetsecurity_token = data["hornetsecurity_token"]

        self.HIERARCHY_GET = "https://cp.hornetsecurity.com/api/v0/hierarchy/"
        self.AUDITS_SEARCH = "https://cp.hornetsecurity.com/api/v0/auditing/_search/"
        self.EMAILS_SEARCH = "https://cp.hornetsecurity.com/api/v0/emails/_search/"

        self.root_id = ""


    def get_root_hierarchy(self) -> str:
        """
        Get root hierarchy id to use it as an 'object_id' later to gather logs
        """
        try:
            resp = get(
                url = self.HIERARCHY_GET,
                params = {"limit": 1, "offset": 0},
                headers = {"Authorization": f"Token {self.hornetsecurity_token}"},
                timeout=10,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl)

            resp.raise_for_status()
            json_resp = resp.json()
            return json_resp['hierarchy'][0]['id']

        except (TimeoutError, ConnectionError, HTTPError) as e:
            logger.error(f"[{__parser__}][get_root_hierarchy]: Error while fetching root hierarchy: {e}",
                         extra={'frontend': str(self.frontend)})
            raise HornetSecurityAPIError("Error while querying Root Hierarchy")
        except JSONDecodeError as e:
            logger.error(f"[{__parser__}][get_root_hierarchy]: Could not decode json response: {e}",
                         extra={'frontend': str(self.frontend)})
            raise HornetSecurityAPIError("Failed to decode json response")
        except (KeyError, TypeError, IndexError) as e:
            logger.error(f"[{__parser__}][get_root_hierarchy]: Could not get valid ID from response: {e}",
                         extra={'frontend': str(self.frontend)})
            raise HornetSecurityAPIError("Could not get hierarchy ID from response")


    def execute_query(self, kind: str, since: datetime, to: datetime, limit: int, offset: int) -> tuple[int, list]:
        params = {"object_id": self.root_id}
        data = {
            "date_from": datetime.strftime(since, "%Y-%m-%dT%H:%M:%SZ"),
            "date_to": datetime.strftime(to, "%Y-%m-%dT%H:%M:%SZ"),
            "limit": limit,
            "offset": offset
        }
        if kind == "auditing":
            url = self.AUDITS_SEARCH
        elif kind == "emails":
            url = self.EMAILS_SEARCH
        else:
            raise HornetSecurityAPIError(f"Unknown kind {kind}")

        retry = 1
        while retry <= 3:
            try:
                logger.info(f"[{__parser__}][execute_query] Querying {url} with parameters {params} "\
                            f"and data {data}")
                resp = post(
                    url = url,
                    params = params,
                    headers = {
                        "APP-ID": self.hornetsecurity_app_id,
                        "Authorization": f"Token {self.hornetsecurity_token}"
                    },
                    data = data,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl,
                    timeout = 10)

                resp.raise_for_status()
                json_resp = resp.json()

                # Handles more than 10k logs to retrieve in a single query
                toRetrieve = int(json_resp.get('num_found_items', 0))
                if toRetrieve >= 10000: # error_id returned by API in this case is 3089
                    return toRetrieve, []

                if kind == "auditing":
                    return toRetrieve, json_resp.get('auditings', [])
                elif kind == "emails":
                    return toRetrieve, json_resp.get('emails', [])
            except HTTPError as e:
                e.response.status_code
                logger.warning(f"[{__parser__}][execute_query]: Received {e.response.status_code} "\
                               f"status code while fetching logs: {e.response.content}",
                               extra={'frontend': str(self.frontend)})
                retry += 1
                continue
            except (TimeoutError, ConnectionError) as e:
                logger.warning(f"[{__parser__}][execute_query]: Network error while fetching logs: {e}",
                               extra={'frontend': str(self.frontend)})
                retry += 1
                continue
            except JSONDecodeError as e:
                logger.error(f"[{__parser__}][execute_query]: Failed to decode json response: {e}",
                             extra={'frontend': str(self.frontend)})
                raise HornetSecurityAPIError("Failed to decode JSON reply")
            except (TypeError, ValueError) as e:
                logger.error(f"[{__parser__}][execute_query]: Failed to get amount of logs to retrieve: {e}",
                             extra={'frontend': str(self.frontend)})
                raise HornetSecurityAPIError("Failed to get info from log")

        msg = f"Failed to fetch {kind} logs after {retry - 1} tries"
        logger.error(f"[{__parser__}][execute_query]: {msg}", extra={'frontend': str(self.frontend)})
        raise HornetSecurityAPIError(msg)


    def get_logs(self, kind: str, initial_since: datetime, initial_to: datetime) -> tuple[list, datetime]:
        """
        Get logs by kind specification and (since; to) couple
        If there is more than 10000 logs to retrieve, the collector continuously divide the range of time to get by two;
        reducing probability to encounters more than the limit number of logs
            -> there is no possibility to query with a request containing an (offset + limit) >= 10 000
            -> there is no possibility to sort
            -> by default logs are timestamp descendently sorted (thus we always retrieve the max serie timestamp
                on the first chunk's log)
        """
        # API doesn't supports microseconds precision we must remove it
        since = initial_since.replace(microsecond=0)
        to = initial_to.replace(microsecond=0)

        ret = []
        count = 1 # to trigger first loop execution

        limit = 1000
        while (len(ret) < count and not self.evt_stop.is_set()):
            count, logs = self.execute_query(kind, since, to, limit, len(ret))
            if count >= 10000:
                to = since + ((to - since) / 2)
                ret = []
                logger.info(f"[{__parser__}][get_logs]: We've tried to retrieve more than 10k {kind} in one query "\
                            f"({count}) - dividing the range of time by 2 -> {since.isoformat(), to.isoformat()}",
                            extra={'frontend': str(self.frontend)})
                continue
            elif count > 0:
                ret.extend(logs)

            self.update_lock()

        if self.evt_stop.is_set() and ret != count: # partial logs retrieved -> we must return with an unmodified to
            return [], initial_to.replace(microsecond=0)

        return ret, to


    def format_log(self, kind: str, log: dict) -> str:
        def is_ascii(s):
            return all(ord(c) < 128 for c in s)

        log['kind'] = kind

        ## EMAILS
        if kind == "emails":
            # size
            size : dict = log.get('size', {})
            if size:
                value : int = size.get('value', 0)
                unit : str = size.get('unit', "kb")
                unit = unit.lower()

                unit_table = {"kb": 1000, "mb": 1000000, "gb": 1000000000}
                log['size'] = value * unit_table.get(unit, 0)

            # attachments
            new_attachments = []
            for attachment in log.get('attachments', []):
                new_attachment = {"file": {}}
                if attachment.get("name"):
                    new_attachment['file']['name'] = attachment["name"]
                if attachment.get("checksum"):
                    new_attachment['file']['md5'] = attachment["checksum"]
                new_attachments.append(new_attachment)
            log['attachments'] = new_attachments

            # crypt_type_*
            crypt_type_in_text = log.get('crypt_type_in', {}).get('text')
            if isinstance(crypt_type_in_text, str):
                log['crypt_type_in'] = crypt_type_in_text.lower()
            else:
                log['crypt_type_in'] = "unknown"

            crypt_type_out_text = log.get('crypt_type_out', {}).get('text')
            if isinstance(crypt_type_out_text, str):
                log['crypt_type_out'] = crypt_type_out_text.lower()
            else:
                log['crypt_type_out'] = "unknown"

            # direction
            direction = log.get('direction')
            if direction == 1:
                log['direction'] = "inbound"
            elif direction == 2:
                log['direction'] = "outbound"
            else:
                log['direction'] = "unknown"

            # classification
            classification_text = log.get('classification', {}).get('text')
            if isinstance(classification_text, str):
                log['classification'] = classification_text.lower()
            else:
                log['classification'] = "unknown"

            # status
            status_text = log.get('status', {}).get('text')
            if isinstance(status_text, str):
                log['status'] = status_text.lower()
            else:
                log['status'] = "unknown"

            # is_archived
            is_archived = log.get('is_archived')
            if not isinstance(is_archived, bool):
                log['is_archived'] = False

            # has_url_rewritten
            has_url_rewritten = log.get('has_url_rewritten')
            if not isinstance(has_url_rewritten, bool):
                log['has_url_rewritten'] = False

            # private
            private = log.get('private')
            if not isinstance(private, bool):
                log['private'] = False

            # subject
            subject = log.get('subject')
            log['is_subject_encoded'] = False
            if isinstance(subject, str) and not is_ascii(subject):
                try:
                    log['subject'] = str(b64encode(subject.encode('utf-8')))
                    log['is_subject_encoded'] = True
                except (ValueError, TypeError): # Failed to b64 or utf8 encode
                    log['subject'] = ""

            # destination_hostname
            destination_hostname : str = log.get('destination_hostname', "")
            if destination_hostname and "[" in destination_hostname:
                log['destination_hostname'] = destination_hostname.split('[')[0]
            else:
                log['destination_hostname'] = ""

        ## AUDITING
        elif kind == "auditing":
            # new_values
            new_values = log.get('new_values')
            if new_values:
                try:
                    new_values = loads(new_values)
                except JSONDecodeError as e:
                    raise HornetSecurityAPIError(e)
                if not isinstance(new_values, dict):
                    log['new_values'] = {}
                else:
                    subject = new_values.get('subject')
                    if isinstance(subject, str) and not is_ascii(subject):
                        new_values['is_subject_encoded'] = False
                        try:
                            new_values['subject'] = str(b64encode(subject.encode('utf-8')))
                            new_values['is_subject_encoded'] = True
                        except (ValueError, TypeError): # Failed to b64 or utf8 encode
                            log['subject'] = ""
                    log['new_values'] = new_values

            # old_values
            old_values = log.get('old_values')
            if old_values:
                try:
                    old_values = loads(old_values)
                except JSONDecodeError as e:
                    raise HornetSecurityAPIError(e)
                if not isinstance(old_values, dict):
                    log['old_values'] = {}
                else:
                    subject = old_values.get('subject')
                    if isinstance(subject, str) and not is_ascii(subject):
                        old_values['is_subject_encoded'] = False
                        try:
                            old_values['subject'] = str(b64encode(subject.encode('utf-8')))
                            old_values['is_subject_encoded'] = True
                        except (ValueError, TypeError): # Failed to b64 or utf8 encode
                            log['subject'] = ""
                    log['old_values'] = old_values

        return dumps(log)


    def execute(self):
        # Get hierarchy root
        self.root_id = self.get_root_hierarchy()

        for kind in ["auditing", "emails"]:
            since = self.last_collected_timestamps.get(f"hornetsecurity_{kind}") or (timezone.now() - timedelta(days=7))
            to = min(timezone.now() - timedelta(minutes=3), since + timedelta(days=1))

            new_logs, new_to = self.get_logs(kind, since, to)

            if new_logs:
                logger.info(f"[{__parser__}][execute]: Successfully got {len(new_logs)} {kind}'s logs "\
                            "from {since} to {new_to}", extra={'frontend': str(self.frontend)})
                self.write_to_file([self.format_log(kind, log) for log in new_logs])
                self.update_lock()

                # this incrementation is mandatory to not get doublons for every request - overlapping from one range
                # to another - even if it's uggly and possibly causing logs missing
                self.last_collected_timestamps[f"hornetsecurity_{kind}"] = new_to + timedelta(seconds=1)
                logger.info(f"[{__parser__}][execute]: Updated last_collected_timestamps['hornetsecurity_{kind}'] "\
                            f"to {new_to}", extra={'frontend': str(self.frontend)})
            else:
                logger.info(f"[{__parser__}][execute]: No new log received for {kind} logs",
                            extra={'frontend': str(self.frontend)})
                if since < timezone.now() - timedelta(hours=24):
                    logger.info(f"[{__parser__}][execute]: No log for the last 24 hours, updating the 'since' "\
                                "value 1 hour forward", extra={'frontend': str(self.frontend)})
                    self.last_collected_timestamps[f"hornetsecurity_{kind}"] = since + timedelta(hours=1)


    def test(self):
        # Get hierarchy root
        self.root_id = self.get_root_hierarchy()

        try:
            logger.debug(f"[{__parser__}][test]:Running tests...", extra={'frontend': str(self.frontend)})

            since = timezone.now() - timedelta(minutes=15)
            to = timezone.now()

            logs = []
            auditing, _ = self.get_logs("auditing", since, to)
            emails, _ = self.get_logs("emails", since, to)
            logs.extend(auditing)
            logs.extend(emails)
            logs = logs[0:9] # gui/browser is lagging when showing up more than 100 logs

            msg = f"{len(auditing)} auditing and {len(emails)} emails logs fetched"
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
