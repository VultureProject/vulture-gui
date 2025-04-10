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
__doc__ = 'Armis Centrix API Parser toolkit'
__parser__ = 'ArmisCentrix'

import logging
from datetime import timedelta, datetime
from requests import exceptions, session
from urllib.parse import quote
from json import dumps, JSONDecodeError
from copy import deepcopy

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ArmisCentrixAPIError(Exception):
    pass


class ArmisCentrixParser(ApiParser):
    # last slash is mandatory for endpoints
    AUTH_URL   = "/api/v1/access_token/"
    SEARCH_URL = "/api/v1/search/"

    LIMIT = 1000 # maximum limit is 9999 (ELK)


    def __init__(self, data):
        super().__init__(data)

        self.armis_host = data["armis_centrix_host"]
        self.armis_secretkey = data["armis_centrix_secretkey"]
        self.armis_get_activity_logs = data.get("armis_centrix_get_activity_logs", False)

        self.armis_token           = data.get("armis_centrix_token", None)
        self.armis_token_expire_at = data.get("armis_centrix_token_expire_at", None)

        self.armis_host = f"https://{self.armis_host.split('://')[-1].strip('/')}"

        self.session = None

    def test(self):
        try:
            self.login() # establish a session to the console
            logger.info(f"[{__parser__}][test] :: Running tests...", extra={'frontend': str(self.frontend)})

            since = timezone.now() - timedelta(days=1)
            to    = timezone.now()

            logs = []
            _, _, alerts = self.get_logs("alerts", since, to)
            logs += alerts
            if self.armis_get_activity_logs:
                _, _, activities = self.get_logs("activity", since, to)
                logs += activities

            msg = f"{len(logs)} logs retrieved"
            logger.info(f"[{__parser__}][test] :: {msg}", extra={'frontend': str(self.frontend)})
            return {"status": True, "data": logs}

        except Exception as e:
            logger.exception(f"[{__parser__}][test] :: {e}", extra={'frontend': str(self.frontend)})
            return {"status": False, "error": str(e)}


    def login(self) -> None:
        if not self.session:
            self.session = session()
            self.session.headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }

        if not self.armis_token or (self.armis_token_expire_at <= (timezone.now() + timedelta(minutes=5))):
            # ask for a new token to API (token expiration seems to be by default to 15minutes)
            resp = self.execute_query(
                method="POST",
                url=f"{self.armis_host}{self.AUTH_URL}",
                query={'secret_key': self.armis_secretkey}
            )
            assert resp.get("success", None), f"Cannot retrieve token from API (success!=true): {resp}"

            token = resp.get("data", {}).get("access_token", "")
            token_expire_at = resp.get("data", {}).get("expiration_utc", "")
            token_expire_at = datetime.strptime(token_expire_at, "%Y-%m-%dT%H:%M:%S.%f%z")
            assert token, "Cannot retrieve token from API data['access_token'] = Null"
            assert token_expire_at and isinstance(token_expire_at, datetime), "Cannot retrieve token_expire_at from API data['expiration_utc'] = Null or invalid datetime"
            self.armis_token = token
            self.armis_token_expire_at = token_expire_at

            self.save_access_token()

            self.session.headers.update({"Authorization": token})
            logger.info(f"[{__parser__}][login] :: Successfully regenerate token", extra={'frontend': str(self.frontend)})

        else: # use the non-expired access token
            self.session.headers.update({"Authorization": self.armis_token})

        logger.info(f"[{__parser__}][login] :: Successfully logged in", extra={'frontend': str(self.frontend)})

    def save_access_token(self) -> None:
        try:
            if self.frontend:
                self.frontend.armis_centrix_token = self.armis_token
                self.frontend.armis_centrix_token_expire_at = self.armis_token_expire_at
                self.frontend.save(update_fields=['armis_centrix_token', 'armis_centrix_token_expire_at'])
        except Exception as e:
            raise ArmisCentrixAPIError(f"Unable to save access token: {e}")


    def execute_query(self, method: str, url: str, query: dict, timeout: int = 10) -> dict:
        retry = 3
        response = None
        while(retry > 0 and not self.evt_stop.is_set()):
            retry -= 1
            try:
                query_tolog = deepcopy(query)
                if query_tolog.get("secret_key"):
                    query_tolog["secret_key"] = "REDACTED"

                logger.info(f"[{__parser__}][execute_query] :: Querying ({method}) {url} with query {query_tolog} (retries: {retry})", extra={'frontend': str(self.frontend)})
                if method == "GET":
                    response = self.session.get(
                        url,
                        params=query,
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                    )
                elif method == "POST":
                    response = self.session.post(
                        url,
                        data=dumps(query),
                        headers={'Content-Type': 'application/json'},
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                    )
            except exceptions.ReadTimeout:
                logger.error(f"[{__parser__}][execute_query] :: Encounters a ReadTimeout, sleeping {timeout} seconds and retry (retries left: {retry}/3)", extra={'frontend': str(self.frontend)})
                self.evt_stop.wait(10.0)
                continue
            if response and response.status_code == 401:
                logger.error(f"[{__parser__}][execute_query] :: Got a 401 status code, reseting authentication...", extra={'frontend': str(self.frontend)})
                logger.info(f"[{__parser__}][execute_query] :: access token was expiring at ({self.armis_token_expire_at})", extra={'frontend': str(self.frontend)})
                self.armis_token = None # resets expired token
                self.armis_token_expire_at = None
                self.login()
                continue
            break  # no error we can break

        try:
            response.raise_for_status()
            return response.json()
        except JSONDecodeError:
            logger.exception(f"[{__parser__}][execute_query] :: Server answer not a valid json (status code {response.status_code})", extra={'frontend': str(self.frontend)})
            raise ArmisCentrixAPIError("Invalid JSON")
        except exceptions.HTTPError:
            logger.exception(f"[{__parser__}][execute_query] :: Server answers with an invalid response : status ({response.status_code}) - response ({response.content})", extra={'frontend': str(self.frontend)})
            raise ArmisCentrixAPIError(f"Response code {response.status_code}")
        except AttributeError:
            #In case response is None
            logger.exception(f"[{__parser__}][execute_query] :: Querying logs failed", extra={'frontend': str(self.frontend)})
            raise ArmisCentrixAPIError("No response")


    def get_logs(self, kind: str, since: datetime, to: datetime, offset: int = 0) -> tuple:
        logs = []

        try:
            since = since.strftime("%Y-%m-%dT%H:%M:%S")
            to    =    to.strftime("%Y-%m-%dT%H:%M:%S")

            url = f"{self.armis_host}{self.SEARCH_URL}"
            if kind == "alerts":
                url += "?aql=" + quote(f'in:alerts after:{since} before:{to} orderBy:(time asc)')
            elif kind == "activity":
                url += "?aql=" + quote(f'in:activity after:{since} before:{to} orderBy:(time asc)')
            params = {
                "length": self.LIMIT, # page size
                "includeSample": "false",
                "includeTotal": "false",
                "from": offset
            }

            resp = self.execute_query(
                url=url,
                method="GET",
                query=params
            )
            logs = resp["data"]["results"]
            totalToRetrieve = resp["data"]["total"]

            return len(logs), totalToRetrieve, logs

        except Exception as e:
            logger.exception(f"[{__parser__}][get_logs] :: Error querying {kind} logs", extra={'frontend': str(self.frontend)})
            raise Exception(e)


    def format_log(self, log: dict) -> str:
        try:
            # source.ip, destination.ip, source.mac, destination.mac
            src_ips = []
            src_macs = []
            for src_endpoint in log.get("sourceEndpoints", []):
                sip = src_endpoint.get("ip")
                if isinstance(sip, str):
                    src_ips.append(sip)
                elif isinstance(sip, list):
                    src_ips.extend(sip)
                smac = src_endpoint.get("macAddress")
                if isinstance(smac, str):
                    src_macs.append(smac)
                elif isinstance(smac, list):
                    src_macs.extend(smac)
            dst_ips = []
            dst_macs = []
            for dst_endpoint in log.get("destinationEndpoints", []):
                dip = dst_endpoint.get("ip")
                if isinstance(dip, str):
                    dst_ips.append(dip)
                elif isinstance(dip, list):
                    dst_ips.extend(dip)
                dmac = dst_endpoint.get("macAddress")
                if isinstance(dmac, str):
                    dst_macs.append(dmac)
                elif isinstance(dmac, list):
                    dst_macs.extend(dmac)

            log["custom_ip-mac"] = {
                "src_ips": src_ips or ["0.0.0.1"],
                "src_macs": src_macs or ["00:00:00:00:00:00"],
                "dst_ips": dst_ips or ["0.0.0.1"],
                "dst_macs": dst_macs or ["00:00:00:00:00:00"]
            }

            # threat.*
            if log.get("alertId"):
                subtechnique_ids = []
                subtechnique_names = []
                tactic_ids = []
                tactic_names = []
                technique_ids = []
                technique_names = []

                if labels := log.get("mitreAttackLabels", []):
                    for label in labels:
                        if subtechnique := label.get("subTechnique"):
                            subtechnique = subtechnique.split(" ")
                            if isinstance(subtechnique[0], str):
                                subtechnique_ids.append(subtechnique[0])
                            elif isinstance(subtechnique[0], list):
                                subtechnique_ids.extend(subtechnique[0])
                            if isinstance(subtechnique[1], str):
                                subtechnique_names.append(subtechnique[1])
                            elif isinstance(subtechnique[1], list):
                                subtechnique_names.extend(subtechnique[1])
                        if tactic := label.get("tactic"):
                            tactic = tactic.split(" ")
                            if isinstance(tactic[0], str):
                                tactic_ids.append(tactic[0])
                            elif isinstance(tactic[0], list):
                                tactic_ids.extend(tactic[0])
                            if isinstance(tactic[1], str):
                                tactic_names.append(tactic[1])
                            elif isinstance(tactic[1], list):
                                tactic_names.extend(tactic[1])
                        if technique := label.get("technique"):
                            technique = technique.split(" ")
                            if isinstance(technique[0], str):
                                technique_ids.append(technique[0])
                            elif isinstance(technique[0], list):
                                technique_ids.extend(technique[0])
                            if isinstance(technique[1], str):
                                technique_names.append(technique[1])
                            elif isinstance(technique[1], list):
                                technique_names.extend(technique[1])

                    log["custom_mitre"] = {
                        "tactic": {"ids": tactic_ids, "names": tactic_names},
                        "technique": {"ids": technique_ids, "names": technique_names},
                        "subtechnique": {"ids": subtechnique_ids, "names": subtechnique_names}
                    }

            return dumps(log)

        except Exception as e:
            msg = f"Failed to format log {log.get('alertId') or log.get('activityUUID')} - {e}"
            logger.error(f"[{__parser__}][format_log] :: {msg}", extra={'frontend': str(self.frontend)})
            return "" # this empty value is deleted before writing lines to rsyslog (she serves to not stop the execution of the collector prematurely)


    def execute(self):
        self.login()

        kinds = ["alerts"]
        if self.armis_get_activity_logs:
            kinds.append("activity")

        for kind in kinds:
            # API have the capability to get back in time from the last 100 days at maximum
            since = self.last_collected_timestamps.get(f"armis_centrix_{kind}") or (timezone.now() - timedelta(days=30))
            # collect at max 24h of range to avoid API taking too long to answer and delay by 3 minutes to avoid missing alerts due to ELK insertion time
            to    = min(timezone.now() - timedelta(minutes=3), since + timedelta(hours=24))
            offset = 0

            # get first page of logs
            logger.info(f"[{__parser__}][execute] :: Querying {kind} from {since} to {to}", extra={'frontend': str(self.frontend)})
            logs_len, total, logs = self.get_logs(kind=kind, since=since, to=to, offset=offset)
            offset += logs_len
            self.write_to_file([self.format_log(log) for log in logs if log != ""])
            self.update_lock()

            # paginate if necessary to get remaining pages
            while offset < total:
                logs_len, total, logs = self.get_logs(kind=kind, since=since, to=to, offset=offset)
                offset += logs_len
                self.write_to_file([self.format_log(log) for log in logs if log != ""])
                self.update_lock()

            # update timestamps
            if offset > 0:
                logger.info(f"[{__parser__}][execute] :: Successfully gets {offset} {kind} logs, updating last_collected_timestamps['armis_centrix_{kind}'] -> {to}", extra={'frontend': str(self.frontend)})
                self.last_collected_timestamps[f"armis_centrix_{kind}"] = to
            elif since < timezone.now() - timedelta(hours=24):
                # if no logs retrieved and the last_collected_timestamp is older than 24h
                # move one hour forward to prevent stagnating ad vitam eternam
                self.last_collected_timestamps[f"armis_centrix_{kind}"] = since + timedelta(hours=1)

            if self.evt_stop.is_set():
                break

        logger.info(f"[{__parser__}][execute] :: Parsing done.", extra={'frontend': str(self.frontend)})
