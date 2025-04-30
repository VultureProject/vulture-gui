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
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Hornet Security API Parser toolkit'
__parser__ = 'HORNETSECURITY'


from requests.sessions import Session
from json import dumps
from datetime import datetime, timedelta

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

        self.session = Session()

        self.HIERARCHY_GET = "https://cp.hornetsecurity.com/api/v0/hierarchy/"
        self.AUDITS_SEARCH = "https://cp.hornetsecurity.com/api/v0/auditing/_search/"
        self.EMAILS_SEARCH = "https://cp.hornetsecurity.com/api/v0/emails/_search/"

        # Get hierarchy root
        self.root_id = self.get_root_hierarchy()


    def get_root_hierarchy(self) -> str:
        """
        Get root hierarchy id to use it as an 'object_id' later to gather logs
        """
        resp = self.session.get(
            url = self.HIERARCHY_GET,
            params = {"limit": 1, "offset": 0},
            headers = {"Authorization": f"Token {self.hornetsecurity_token}"})
        try:
            json_resp = resp.json()
        except Exception as e:
            raise HornetSecurityAPIError(f"Failed to decode json response - {resp.content} -- {e}")

        hierarchy = json_resp.get('hierarchy', {})
        if hierarchy[0] if hierarchy else None:
            if hierarchy[0].get('id'):
                return hierarchy[0]['id']

        msg = f"Fail to get hierarchy id -- {resp.content}"
        logger.exception(f"[{__parser__}][get_root_hierarchy]: {msg}", extra={'frontend': str(self.frontend)})
        raise HornetSecurityAPIError(msg)


    def execute_query(self, kind: str, since: datetime, to: datetime, limit: int, offset: int) -> tuple[str, int, list]:
        since = datetime.strftime(since, "%Y-%m-%dT%H:%M:%SZ")
        to = datetime.strftime(to, "%Y-%m-%dT%H:%M:%SZ")

        retry = 3
        while retry > 0:
            try:
                if kind == "auditing":
                    resp = self.session.post(
                        url = self.AUDITS_SEARCH,
                        params = {"object_id": self.root_id},
                        headers = {"APP-ID": self.hornetsecurity_app_id, "Authorization": f"Token {self.hornetsecurity_token}"},
                        data = {"date_from": since, "date_to": to, "limit": limit, "offset": offset},
                        timeout = 10)
                elif kind == "emails":
                    resp = self.session.post(
                        url = self.EMAILS_SEARCH,
                        params = {"object_id": self.root_id},
                        headers = {"APP-ID": self.hornetsecurity_app_id, "Authorization": f"Token {self.hornetsecurity_token}"},
                        data = {"date_from": since, "date_to": to, "limit": limit, "offset": offset},
                        timeout = 10)

            except Exception as e:
                logger.exception(f"[{__parser__}][execute_query]: Unexpected error while fetching {kind}'s logs - {since, to} -- {e}", extra={'frontend': str(self.frontend)})
                retry -= 1
                continue

            try:
                json_resp = resp.json()
            except Exception as e:
                logger.exception(f"[{__parser__}][execute_query]: Failed to decode json response {resp.content} -- {e}", extra={'frontend': str(self.frontend)})

            # Handles more than 10k logs to retrieve in a single query
            toRetrieve = json_resp.get('num_found_items', 0)
            if toRetrieve >= 10000: # error_id returned by API in this case is 3089
                return "divide", toRetrieve, []

            # resp.raise_for_status()
            if resp.status_code != 200:
                logger.exception(f"[{__parser__}][execute_query]: Receive {resp.status_code} != 200 while fetching {kind}'s logs - {since, to} -- {resp.content}", extra={'frontend': str(self.frontend)})
                retry -= 1
                continue

            if kind == "auditing":
                return "write", toRetrieve, json_resp.get('auditings', [])
            elif kind == "emails":
                return "write", toRetrieve, json_resp.get('emails', [])

        msg = f"Fail to fetch {kind} by encountering more than 3 errors consecutively {since, to}"
        logger.exception(f"[{__parser__}][execute_query]: {msg}", extra={'frontend': str(self.frontend)})
        raise HornetSecurityAPIError(msg)


    def get_logs(self, kind: str, since: datetime, to: datetime) -> tuple[list, datetime]:
        """
        Get logs by kind specification and (since; to)
        Don't know if timerange is exclusive or inclusive as now
        If there is more than 10000 logs to retrieve, we will miss somes as :
            -> there is no possibility to query with a request validating : (offset + limit) >= 10 000
            -> there is no possibility to sort AND by default logs are descendently sorted (so the max timestamp received will always be the last timestamp stored in ELK)
        ==
            The only way I found to limit impact of this behavior is to divide period of time by 2 
            if more than 10k logs tries to be fetched and redo it every time this condition satisfies (thus discarding log's writing)
        ==
        """
        # API doesn't supports microseconds precision
        since = since.replace(microsecond=0)
        to = to.replace(microsecond=0)

        ret = []

        limit = 1000
        op, count, logs = self.execute_query(kind, since, to, limit, len(ret))
        if op == "divide":
            to = since + ((to - since) / 2)
            logger.info(f"[{__parser__}][get_logs]: We've tried to retrieve more than 10k {kind} in one query ({count}) - dividing the range of time by 2 -> {since.isoformat(), to.isoformat()}", extra={'frontend': str(self.frontend)})
            pass
        elif op == "write":
            ret.extend(logs)

        while (len(ret) != count and not self.evt_stop.is_set()):
            op, count, logs = self.execute_query(kind, since, to, limit, len(ret))
            if op == "divide":
                to = since + ((to - since) / 2)
                logger.info(f"[{__parser__}][get_logs]: We've tried to retrieve more than 10k {kind} in one query ({count}) - dividing the range of time by 2 -> {since.isoformat(), to.isoformat()}", extra={'frontend': str(self.frontend)})
                continue
            elif op == "write":
                ret.extend(logs)

            self.update_lock()

        return ret, to


    def format_log(self, kind: str, log: dict) -> str:
        log['kind'] = kind

        if kind == "emails":
            # size
            size : dict = log.get('size')
            if size:
                value : int = size.get('value', 0)
                unit : str = size.get('unit', "kb")
                unit = unit.lower()

                unit_table = {"kb": 1000, "mb": 1000000, "gb": 1000000000}
                size = value * unit_table.get(unit, 0)

                log['size'] = size

            # attachments
            attachments : list = log.get('attachments', [])
            new_attachments = []
            if attachments:
                for attachment in attachments:
                    new_attachment = {"file": {}}
                    if attachment.get("name"):
                        new_attachment['file']['name'] = attachment["name"]
                    if attachment.get("checksum"):
                        new_attachment['file']['md5'] = attachment["checksum"]
                    new_attachments.append(new_attachment)
            log['attachments'] = new_attachments

            # crypt_type_*
            crypt_type_in_text : dict = log.get('crypt_type_in', {}).get('text')
            if isinstance(crypt_type_in_text, str):
                log['crypt_type_in'] = crypt_type_in_text.lower()
            else:
                log['crypt_type_in'] = "unknown"

            crypt_type_out_text : dict = log.get('crypt_type_out', {}).get('text')
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
            classification_text : dict = log.get('classification', {}).get('text')
            if isinstance(classification_text, str):
                log['classification'] = classification_text.lower()
            else:
                log['classification'] = "unknown"

            # status
            status_text : dict = log.get('status', {}).get('text')
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

        return dumps(log)


    def execute(self):
        for kind in ["auditing", "emails"]:
            logs = []

            since = self.last_collected_timestamps.get(f"hornetsecurity_{kind}") or (timezone.now() - timedelta(days=7))
            to = min(timezone.now() - timedelta(minutes=3), since + timedelta(days=1))

            new_logs, new_to = self.get_logs(kind, since, to)

            logger.info(f"[{__parser__}][execute]: Successfully get {len(new_logs)} {kind}'s logs from {since} to {new_to}", extra={'frontend': str(self.frontend)})
            logs.extend(new_logs)

            if logs:
                self.write_to_file([self.format_log(kind, log) for log in logs])
                self.update_lock()

            # this incrementation is mandatory to not get doublons for every request - overlapping from one range to another - even if it's uggly and possibly causing logs missing
            self.last_collected_timestamps[f"hornetsecurity_{kind}"] = new_to + timedelta(seconds=1)
            logger.info(f"[{__parser__}][execute]: Updated last_collected_timestamps['hornetsecurity_{kind}'] to {new_to}", extra={'frontend': str(self.frontend)})

    def test(self):
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
