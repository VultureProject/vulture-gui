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
__doc__ = 'Sentinel One EDR API Parser'
__parser__ = 'SENTINEL ONE'


import json
import logging
import requests

from datetime import datetime, timedelta, timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils.timezone import make_aware

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SentinelOneAPIError(Exception):
    pass


class SentinelOneParser(ApiParser):
    LOGIN_URI_TOKEN = "/web/api/v2.1/users/login/by-api-token"
    LOGIN_URI = "/web/api/v2.1/users/login"
    VERSION_URI = "/web/api/v2.1/system/info"
    ACCOUNTS = "/web/api/v2.1/accounts"
    SITES = "/web/api/v2.1/sites"
    AGENTS = "/web/api/v2.1/agents"
    THREATS = "/web/api/v2.1/threats"
    POLICY_BY_SITE = "/web/api/v2.1/sites/{id}/policy"
    ACTIVITIES = "web/api/v2.1/activities"

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json, text/plain, */*'
    }

    def __init__(self, data):
        super().__init__(data)

        self.sentinel_one_host = data["sentinel_one_host"]
        if not self.sentinel_one_host.startswith('https://'):
            self.sentinel_one_host = f"https://{self.sentinel_one_host}"

        self.sentinel_one_apikey = data["sentinel_one_apikey"]

        self.session = None


    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                login_url = f"{self.sentinel_one_host}/{self.LOGIN_URI_TOKEN}"
                logger.info(f"[{__parser__}]:_connect: connecting with endpoint '{login_url}'...", extra={'frontend': str(self.frontend)})

                payload = {
                    "data": {
                        "apiToken": self.sentinel_one_apikey
                    }
                }
                logger.debug(f"[{__parser__}]:_connect: payload is '{payload}'", extra={'frontend': str(self.frontend)})
                response = requests.post(
                    login_url,
                    json=payload,
                    proxies=self.proxies
                ).json()

                assert response.get('data', {}).get('token'), "Cannot retrieve token from API : {}".format(
                    response)
                self.session.headers.update({'Authorization': f"Token {response['data']['token']}"})
                logger.info(f"[{__parser__}]:_connect: access token successfuly retrieved, ready to query", extra={'frontend': str(self.frontend)})

            return True

        except Exception as err:
            raise SentinelOneAPIError(err)


    def __execute_query(self, method, url, query, timeout=10):

        self._connect()
        logger.debug(f"[{__parser__}]:__execute_query: url: '{url}', query: '{query}', method: '{method}'", extra={'frontend': str(self.frontend)})

        if method == "GET":
            response = self.session.get(
                url,
                params=query,
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies
            )
        elif method == "POST":
            response = self.session.post(
                url,
                data=query,
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies
            )
        else:
            raise SentinelOneAPIError(f"Request method unrecognized : {method}")

        if response.status_code != 200:
            raise SentinelOneAPIError(f"Error at SentinelOne API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        logger.info(f"[{__parser__}]:__execute_query: query successful", extra={'frontend': str(self.frontend)})
        return response.json()


    def test(self):
        logger.info(f"[{__parser__}]:test: launching test query (getting logs from 10 days ago)", extra={'frontend': str(self.frontend)})
        try:
            logs = self.get_logs(since=(datetime.utcnow()-timedelta(days=10)).isoformat()+"Z")

            return {
                "status": True,
                "data": [self.format_log(log, "alert") for log in logs['data']]
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, cursor=None, since=None, to=None, activity_logs=False):
        # Format timestamp for query, API wants a Z at the end
        if since:
            if isinstance(since, datetime):
                since = since.isoformat()
            since = since.replace("+00:00", "Z")
            if since[-1] != "Z":
                since += "Z"
        if to:
            if isinstance(to, datetime):
                to = to.isoformat()
            to = to.replace("+00:00", "Z")
            if to[-1] != "Z":
                to += "Z"

        # Activity logs needs another endpoint + another payload
        if activity_logs:
            alert_url = f"{self.sentinel_one_host}/{self.ACTIVITIES}"
            time_field_name = "createdAt"
            query = {
                'activityTypes': '27,65,66,80,81,85,86,133,134,3200,3201,3202,3203,3204,3400'
            }
        else:
            alert_url = f"{self.sentinel_one_host}/{self.THREATS}"
            time_field_name = "updatedAt"
            query = {}

        #query = {'createdAt__gt': since, 'sortBy': "createdAt"} => activity
        #query = {'updatedAt__gt': since, 'sortBy': "updatedAt"} => alerts
        if since:
            query[f"{time_field_name}__gt"] = since
        if to:
            query[f"{time_field_name}__lte"] = to
        query['sortBy'] = time_field_name

        # Handle paginated results
        if cursor:
            query['cursor'] = cursor

        return self.__execute_query("GET", alert_url, query)


    def getAlertComment(self, alertId):
        comment_url = f"{self.sentinel_one_host}/{self.THREATS}/{alertId}/notes"
        ret = self.__execute_query("GET", comment_url, {})
        return ret['data']


    def format_log(self, log, event_kind):
        if event_kind == "alert":
            comments = []
            for comment in self.getAlertComment(log['id']):
                comments.append({
                    'id': comment['id'],
                    'message': comment['text'],
                    'username': comment['creator'],
                    'timestamp': datetime.fromisoformat(comment['createdAt'].replace("Z", "+00:00")).timestamp()
                })
            log['comments'] = comments
            # Retrieve names of techniques of each tactics
            techniques = list()
            for indc in log['indicators']:
                tech = [x['techniques'] for x in indc['tactics']]
                if len(tech) > 0:
                    # always one entry
                    tech = tech.pop()
                techniques += [x['name'] for x in tech]
            log['mitre_techniques'] = list(set(techniques))
            log['needs_attention'] = not log['threatInfo']['automaticallyResolved']
            log['threatInfo']['createdAt'] = datetime.fromisoformat(log['threatInfo']['createdAt'].replace("Z", "+00:00")).timestamp()
        else:
            log['createdAt'] = datetime.fromisoformat(log['createdAt'].replace("Z", "+00:00")).timestamp()
        log['observer_name'] = self.sentinel_one_host.replace("https://", "")
        log['event_kind'] = event_kind
        return json.dumps(log)


    def execute(self):

        since = self.last_api_call or (datetime.now(timezone.utc) - timedelta(hours=24))
        # Fetch at most 24h of logs to avoid the parser running for too long
        to = min(datetime.now(timezone.utc), since + timedelta(hours=24))

        for event_kind in ['alert', 'activity']:
            first = True
            cursor = None

            logger.info(f"[{__parser__}]:execute: getting '{event_kind}' logs", extra={'frontend': str(self.frontend)})

            while cursor or first:

                response = self.get_logs(cursor=cursor, since=since, to=to, activity_logs=event_kind=='activity')

                # Downloading may take some while, so refresh token in Redis
                self.update_lock()

                logs = response['data']
                cursor = response.get('pagination', {}).get('nextCursor')
                first = False

                self.write_to_file([self.format_log(l, event_kind) for l in logs])

                # Writting may take some while, so refresh token in Redis
                self.update_lock()
                if len(logs) > 0:
                    if event_kind == "alert":
                        # timestamps compared by API have a 10ms precision (empiric observation)
                        last_timestamp = datetime.fromisoformat(logs[-1]['threatInfo']['updatedAt'].replace("Z", "+00:00"))+timedelta(milliseconds=10)
                    else:
                        # timestamps compared by API have a 10ms precision (empiric observation)
                        # need to use fromtimestamp() as value in log has been modified by previous format_log()
                        last_timestamp = make_aware(datetime.fromtimestamp(logs[-1]['createdAt'])+timedelta(milliseconds=10))

                    if last_timestamp > self.frontend.last_api_call:
                        self.frontend.last_api_call = last_timestamp

            msg = f"events {event_kind} collected."
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
