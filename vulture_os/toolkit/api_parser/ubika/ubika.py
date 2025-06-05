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
__version__ = "1.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Ubika API Parser toolkit'
__parser__ = 'UBIKA'


from requests import HTTPError, ReadTimeout, get, post

from datetime import datetime, timedelta
from json import JSONDecodeError, dumps

import logging
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')



class UbikaParserError(Exception):
    pass


class UbikaParser(ApiParser):
    MAX_REQUEST_TRIES = 3
    LOGIN_ENDPOINT = "https://login.ubika.io/auth/realms/main/protocol/openid-connect/token"
    BASE_LOGS_ENDPOINT = "https://api.ubika.io/rest/logs.ubika.io/v1/ns/"
    LOGS_KIND = ["security", "traffic"]

    def __init__(self, data):
        super().__init__(data)

        self.ubika_base_refresh_token = data["ubika_base_refresh_token"]
        self.ubika_namespaces = data.get("ubika_namespaces", [])

        self.ubika_access_token = data.get("ubika_access_token")
        self.ubika_refresh_token = data.get("ubika_refresh_token")
        self.ubika_access_expires_at = data.get("ubika_access_expires_at")


    def _save_frontend_attributes(self):
        self.frontend.ubika_access_token = self.ubika_access_token
        self.frontend.ubika_refresh_token = self.ubika_refresh_token
        self.frontend.ubika_access_expires_at = self.ubika_access_expires_at
        self.frontend.save(update_fields=['ubika_access_token', 'ubika_refresh_token', 'ubika_access_expires_at'])


    def login(self) -> None:
        req = {
            "client_id": "rest-api",
            "grant_type": "refresh_token"
        }

        # Either take the current most recent refresh token, or the initial static refresh token when starting collector
        req["refresh_token"] = self.ubika_refresh_token or self.ubika_base_refresh_token

        resp = self.__execute_query(
            method = "POST",
            url = self.LOGIN_ENDPOINT,
            data = req
        )

        try:
            self.ubika_access_token = resp['access_token']
            self.ubika_refresh_token = resp['refresh_token']
            current_time = timezone.now()
            self.ubika_access_expires_at = current_time + timedelta(seconds=resp['expires_in'])
        except KeyError:
            raise UbikaParserError("Could not get necessary info while logging in")

        self._save_frontend_attributes()

        logger.info(f"[{__parser__}][login]: Successfully renewed access / refresh token", extra={'frontend': str(self.frontend)})


    def __execute_query(self, method: str, url: str, data: dict) -> dict:
        retry = 0

        while retry < 3:
            retry += 1
            resp = None
            try:
                # Don't show sensitive information (such as refresh/access tokens) in logs
                cleaned_data = dict(filter(lambda item: item[0] not in ["refresh_token"], data.items()))
                msg = f"[{__parser__}][__execute_query]: {method} {url} with data {cleaned_data} (try {retry}/3)"
                logger.info(f"{msg}", extra={'frontend': str(self.frontend)})

                if method == "GET":
                    resp = get(
                        url = url,
                        headers = {"Authorization": f"Bearer {self.ubika_access_token}"},
                        params = data,
                        proxies = self.proxies,
                        verify = self.api_parser_custom_certificate or self.api_parser_verify_ssl,
                        timeout = 10
                    )
                elif method == "POST":
                    resp = post(
                        url = url,
                        headers = {"Authorization": f"Bearer {self.ubika_access_token}"},
                        data = data,
                        proxies = self.proxies,
                        verify = self.api_parser_custom_certificate or self.api_parser_verify_ssl,
                        timeout = 10
                    )
                else:
                    raise UbikaParserError(f"Unknown request method {method}")

                resp.raise_for_status()
                return resp.json()

            except JSONDecodeError as e:
                msg = f"[{__parser__}][__execute_query]: Failed to decode json response - {e}"
                logger.warning(f"{msg}", extra={'frontend': str(self.frontend)})
            except (ConnectionError, ReadTimeout) as e:
                msg = f"[{__parser__}][__execute_query]: Connection failed -- {e}"
                logger.warning(f'{msg}', extra={'frontend': str(self.frontend)})
            except HTTPError as e:
                if e.response and e.response.status_code == 401:
                    self.ubika_access_token, self.ubika_access_expires_at = None, None
                    self.login()
                    continue
                msg = f"[{__parser__}][__execute_query]: HTTP error: {e}"
                logger.error(f'{msg}', extra={'frontend': str(self.frontend)})
                raise UbikaParserError(e)

        raise UbikaParserError(f"[{__parser__}][__execute_query]: Could not get a valid answer in {self.MAX_REQUEST_TRIES} tries")


    def get_logs(self, url: str, since: datetime, to: datetime) -> list:
        logs = []
        next_token = ""
        last_save_token = ""

        data = {
            "pagination.pageSize": 10001,
            "pagination.realtime": True
        }

        page_end = False
        while not page_end:
            if next_token:
                data["pagination.pageToken"] = next_token
            else:
                data["filters.fromDate"] = int(since.timestamp() * 1000),
                data["filters.toDate"] = int(to.timestamp() * 1000)

            resp = self.__execute_query(
                method = "GET",
                url = url,
                data = data)

            next_token = resp.get('spec', {}).get('nextPageToken', '')
            logger.debug(f"[{__parser__}][get_logs]: Paginate with url = {url}, last_save_token = {last_save_token}, next_token = {next_token}", extra={'frontend': str(self.frontend)})

            if next_token != last_save_token:
                if newLogs := resp.get('spec', {}).get('items', []):
                    logs.extend(newLogs)
                last_save_token = next_token
            else:
                page_end = True

        return logs


    def format_log(self, log: dict) -> str:
        new_request_headers = {}
        if request_headers := log.get('request', {}).get('headers', []):
            for header in request_headers:
                new_key = header.get('key', '').lower()
                new_value = header.get('value')
                if new_key and new_value:
                    new_request_headers[new_key] = new_value
        log['request']['headers'] = new_request_headers

        new_request_cookies = {}
        if request_cookies := log.get('request', {}).get('cookies', []):
            for cookie in request_cookies:
                new_key = cookie.get('key', '').lower()
                new_value = cookie.get('value')
                if new_key and new_value:
                    new_request_cookies[new_key] = new_value
        log['request']['cookies'] = new_request_cookies

        if context_reaction := log.get('context', {}).get('reaction', ''):
            log['context']['reaction'] = context_reaction.lower()

        return dumps(log)


    def test(self):
        logs = []

        try:
            if (not self.ubika_access_token) or (self.ubika_access_expires_at <= (timezone.now() + timedelta(minutes=1))):
                self.login()

            namespace = self.ubika_namespaces[0]
            for kind in self.LOGS_KIND:
                if kind == "security":
                    url = self.BASE_LOGS_ENDPOINT + namespace + "/security-events"
                elif kind == "traffic":
                    url = self.BASE_LOGS_ENDPOINT + namespace + "/traffic-logs"
                else:
                    raise UbikaParserError(f"Unknown log kind {kind}")

                logger.info(f"[{__parser__}][test]:Running tests...", extra={'frontend': str(self.frontend)})

                since = timezone.now() - timedelta(minutes=15)
                to = timezone.now() - timedelta(minutes=5)

                newLogs = self.get_logs(url, since, to)
                logs.extend(newLogs)

                msg = f"{len(logs)} logs retrieved"
                logger.info(f"[{__parser__}][test]: {msg}", extra={'frontend': str(self.frontend)})

                return {
                    "status": True,
                    "data": logs[0:99]
                }
        except Exception as e:
            logger.exception(f"[{__parser__}][test]: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }


    def execute(self):
        if (not self.ubika_access_token) or (self.ubika_access_expires_at <= (timezone.now() + timedelta(minutes=1))):
            self.login()

        for namespace in self.ubika_namespaces:
            for kind in self.LOGS_KIND:
                if kind == "security":
                    url = self.BASE_LOGS_ENDPOINT + namespace + "/security-events"
                elif kind == "traffic":
                    url = self.BASE_LOGS_ENDPOINT + namespace + "/traffic-logs"
                else:
                    raise UbikaParserError(f"Unknown log kind {kind}")

                current_time = timezone.now()
                to = None

                while ((not to) or (to < current_time - timedelta(minutes=2))) and (not self.evt_stop.is_set()): # delay collect for 2 minutes
                    since = self.last_collected_timestamps.get(f"ubika_{namespace}_{kind}") or (current_time - timedelta(hours=1))
                    to = min(current_time - timedelta(minutes=2), since + timedelta(minutes=30)) # the more the time range is short, the less our pagination is prone to OOM

                    logs = self.get_logs(url, since, to)

                    logger.info(f"[{__parser__}][get_logs]: Successfully got {len(logs)} logs for namespace '{namespace}', for kind '{kind}', from {since} to {to}", extra={'frontend': str(self.frontend)})

                    self.write_to_file([self.format_log(log) for log in logs])
                    self.update_lock()

                    if not self.evt_stop.is_set():
                        self.last_collected_timestamps[f"ubika_{namespace}_{kind}"] = to

            self.update_lock()
