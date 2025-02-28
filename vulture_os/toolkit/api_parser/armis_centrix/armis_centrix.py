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
from json import dumps

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

        if not self.armis_host.startswith('https://'):
            self.armis_host = f"https://{self.armis_host}"

        self.session = None

    def test(self):
        try:
            self.login(test=True) # establish a session to the console
            logger.info(f"[{__parser__}][test] :: Running tests...", extra={'frontend': str(self.frontend)})

            since = timezone.now() - timedelta(days=1)
            to    = timezone.now()

            logs = []
            logs += self.get_logs("alerts", since, to, test=True)
            if self.armis_get_activity_logs: logs += self.get_logs("activities", since, to, test=True)

            msg = f"{len(logs)} logs retrieved"
            logger.info(f"[{__parser__}][test] :: {msg}", extra={'frontend': str(self.frontend)})
            return {"status": True, "data": logs}

        except Exception as e:
            logger.exception(f"[{__parser__}][test] :: {e}", extra={'frontend': str(self.frontend)})
            return {"status": False, "error": str(e)}


    def login(self, test: bool = False) -> None:
        if not self.session:
            self.session = session()
            self.session.headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }

        if not self.armis_token or (self.armis_token_expire_at <= (timezone.now() + timedelta(minutes=5)).timestamp()):
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
            assert token, f"Cannot retrieve token from API data['access_token'] = Null"
            assert token_expire_at and isinstance(token_expire_at, datetime), f"Cannot retrieve token_expire_at from API data['expiration_utc'] = Null or invalid datetime"
            if not test:
                self.frontend.armis_centrix_token = token
                self.frontend.armis_centrix_token_expire_at = token_expire_at.timestamp()
            self.session.headers.update({"Authorization": token})

            logger.info(f"[{__parser__}][login] :: Successfully regenerate token", extra={'frontend': str(self.frontend)})

        else: # use the non-expired access token
            self.session.headers.update({"Authorization": self.frontend.armis_centrix_token})

        logger.info(f"[{__parser__}][login] :: Successfully logged in", extra={'frontend': str(self.frontend)})


    def execute_query(self, method: str, url: str, query: dict, timeout: int = 10) -> dict:
        retry = 3
        while(retry > 0):
            retry -= 1
            try:
                if(method == "GET"):
                    response = self.session.get(
                        url,
                        params=query,
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                    )
                elif(method == "POST"):
                    response = self.session.post(
                        url,
                        data=dumps(query),
                        headers={'Content-Type': 'application/json'},
                        timeout=timeout,
                        proxies=self.proxies,
                        verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                    )
            except exceptions.ReadTimeout:
                self.evt_stop.wait(10.0)
                msg = f"[{__parser__}][execute_query] :: Encounters a ReadTimeout, sleeping {timeout} seconds and retry (retries left: {retry}/3)"
                logger.info(msg, extra={'frontend': str(self.frontend)})
                continue
            if response.status_code == 401 and response.get("message", "") == "Expired access token.": # maybe a bit too much, this handle the case where token had expired "silently" for an unknown reason
                logger.info(f"[{__parser__}][execute_query] :: Resets expired access token {self.armis_token} - expired_at ({self.armis_token_expire_at})", extra={'frontend': str(self.frontend)})
                self.armis_token = "" # resets expired token
                self.login()
                continue
            break  # no error we can break

        response.raise_for_status()
        try:
            return response.json()
        except Exception as e:
            logger.error(f"[{__parser__}][execute_query] :: Server awnsers with an invalid json response : status ({response.status_code}) - response ({response.content})")
            raise Exception(e)


    def get_logs(self, kind: str, since: datetime, to: datetime, test: bool = False) -> int|list:
        logs = []

        try:
            since = since.strftime("%Y-%m-%dT%H:%M:%S")
            to    =    to.strftime("%Y-%m-%dT%H:%M:%S")

            url = f"{self.armis_host}{self.SEARCH_URL}"
            if kind == "alerts":
                url += "?aql=" + quote(f'in:alerts after:{since} before:{to}')
            elif kind == "activities":
                url += "?aql=" + quote(f'in:activity after:{since} before:{to}')
            params = {
                "length": self.LIMIT, # page size
                "includeSample": "false",
                "includeTotal": "false"
            }
            # get the first page of logs
            resp = self.execute_query(
                url=url,
                method="GET",
                query=params
            )
            logs = resp["data"]["results"]
            totalToRetrieve = resp["data"]["total"]

            if test: return logs  # in case of test function exection we want to return the logs as is without paginating

            self.write_to_file([self.format_log(log) for log in logs if log != ""]) # write the first n log's page
            logger.debug(f"[{__parser__}][get_logs] :: Successfully gathered first {kind} page ({len(logs)}/{totalToRetrieve} logs) - {url}/{params}", extra={'frontend': str(self.frontend)})

            # paginate if necessary to get remaining pages
            params["from"] = len(logs) # initialize offset
            while params["from"] < totalToRetrieve:
                new_page = self.execute_query(
                    url = url,
                    method="GET",
                    query=params
                )
                logs = new_page["data"]["results"]
                params["from"] += len(logs) # increment offset
                self.write_to_file([self.format_log(log) for log in logs if log != ""])
                self.update_lock()
                logger.debug(f"[{__parser__}][get_logs] :: Successfully gathered additionnals {kind} page ({params['from']}/{totalToRetrieve} logs) - {url}/{params} - {params['from']}/{totalToRetrieve}", extra={'frontend': str(self.frontend)})

            return params["from"] # return total logs fetched

        except Exception as e:
            logger.error(f"[{__parser__}][get_logs] :: Error querying {kind} logs")
            raise Exception(e)

    def format_log(self, log: dict) -> str:
        try:
            return dumps(log)
        except Exception as e:
            msg = f"Failed to json encode log {log.get('alertId') or log.get('activityUUID')} - {e}"
            logger.error(f"[{__parser__}][format_log] :: {msg}")
            return "" # this empty value is deleted before writing lines to rsyslog (she serves to not stop the execution of the collector prematurely)


    def execute(self):
        self.login()

        kinds = ["alerts"]
        if self.armis_get_activity_logs: kinds.append("activities")

        for kind in kinds:
            # API have the capability to get back in time from the last 100 days at maximum
            since = self.last_collected_timestamps.get(f"armis_centrix_{kind}") or (timezone.now() - timedelta(days=30))
            # collect at max 24h of range to avoid API taking too long to awnser and delay by 3minutes to avoid missing alerts due to ELK insertion time
            to    = min(timezone.now() - timedelta(minutes=3), since + timedelta(hours=24))

            logger.info(f"[{__parser__}][execute] :: Querying {kind} from {since} to {to}", extra={'frontend': str(self.frontend)})
            logs_len = self.get_logs(kind=kind, since=since, to=to)

            if logs_len > 0:
                logger.info(f"[{__parser__}][execute] :: Successfully gets {logs_len} {kind} logs, updating last_collected_timestamps['armis_centrix_{kind}'] -> {to}", extra={'frontend': str(self.frontend)})
                self.last_collected_timestamps[f"armis_centrix_{kind}"] = to
            elif since < timezone.now() - timedelta(hours=24):
                # if no logs retrieved and the last_collected_timestamp is older than 24h
                # move one hour forward to prevent stagnating ad vitam eternam
                self.last_collected_timestamps[f"armis_centrix_{kind}"] = since + timedelta(hours=1)

        logger.info(f"[{__parser__}][execute] :: Parsing done.", extra={'frontend': str(self.frontend)})
