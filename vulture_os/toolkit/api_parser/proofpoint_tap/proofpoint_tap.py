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
__author__ = "Theo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Proofpoint TAP SIEM API'
__parser__ = 'PROOFPOINT'

import logging
import requests

from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from json import dumps as json_dumps
from json import loads as json_loads
from json import JSONDecodeError
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

MAX_DELETE_ATTEMPTS = 3


class ProofpointTAPParseError(Exception):
    pass


class ProofpointTAPAPIError(Exception):
    pass


class ProofpointTAPAPITooFarError(Exception):
    pass


class ProofpointTAPParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.proofpoint_tap_host = data["proofpoint_tap_host"]
        self.proofpoint_tap_principal = data["proofpoint_tap_principal"]
        self.proofpoint_tap_secret = data["proofpoint_tap_secret"]
        self.proofpoint_tap_endpoint = data["proofpoint_tap_endpoint"]

    def test(self):
        try:
            status, logs = self._get_logs(endpoint="/all", params={"sinceSeconds": 3600})

            if not status:
                return {
                    "status": False,
                    "error": logs
                }

            return {
                "status": True,
                "data": _('Success')
            }
        except ProofpointTAPAPIError as e:
            return {
                "status": False,
                "error": str(e)
            }

    def _get_logs(self, endpoint=None, params={'sinceSeconds': 3600}, allow_redirects=False):
        if endpoint is None:
            endpoint = "/all"

        url = f"{self.proofpoint_tap_host}/v2/siem{endpoint}"
        params['format'] = 'json'

        try:
            response = requests.get(
                url,
                auth=(self.proofpoint_tap_principal, self.proofpoint_tap_secret),
                allow_redirects=allow_redirects,
                params=params,
                proxies=self.proxies
            )
        except requests.ConnectionError as e:
            logger.error(f"[{__parser__}]:_get_logs: {e}", extra={'frontend': str(self.frontend)})
            raise ProofpointTAPAPIError(e)

        if response.status_code == 401:
            return False, _('Authentication failed')
        elif response.status_code == 403:
            return False, _('Cannot access ressource: account is not authorized')
        elif response.status_code == 429:
            return False, _('Rate limited: too many requests')
        elif response.status_code == 400:
            if b"too far into the past" in response.content:
                error = "ProofpointTAP API call: cannot query this far into the past, coming back 12 hours back from now"
                logger.warning(f"[{__parser__}]:_get_logs: {error}", extra={'frontend': str(self.frontend)})
                self.last_api_call = datetime.now(timezone.utc) - timedelta(hours=12)
                raise ProofpointTAPAPITooFarError(error)
            error = f"Error at ProofpointTAP API Call: {response.content}"
            raise ProofpointTAPAPIError(error)
        elif response.status_code != 200:
            error = f"Error at ProofpointTAP API Call ({response.status_code}): {response.content}"
            logger.error(f"[{__parser__}]:_get_logs: {error}", extra={'frontend': str(self.frontend)})
            raise ProofpointTAPAPIError(error)

        content = response.content

        return True, content

    def _parse_logs(self, logs):
        logger.debug(f"[{__parser__}]:_parse_logs: parsing logs", extra={'frontend': str(self.frontend)})
        time_string = ""
        parsed = []
        try:
            json_logs = json_loads(logs)
            time_string = json_logs['queryEndTime']
        except JSONDecodeError as e:
            logger.error(f"[{__parser__}]:_parse_logs: {e}", extra={'frontend': str(self.frontend)})
            raise ProofpointTAPParseError(e)

        logger.debug(f"[{__parser__}]:_parse_logs: "
                     f"got {len(json_logs['messagesBlocked'])} lines for 'messagesBlocked'",
                     extra={'frontend': str(self.frontend)})
        for messageBlocked in json_logs["messagesBlocked"]:
            messageBlocked['messageType'] = 'messagesBlocked'
            parsed.append(messageBlocked)

        logger.debug(f"[{__parser__}]:_parse_logs: "
                     f"got {len(json_logs['messagesDelivered'])} lines for 'messagesDelivered'",
                     extra={'frontend': str(self.frontend)})
        for messageDelivered in json_logs["messagesDelivered"]:
            messageDelivered['messageType'] = 'messagesDelivered'
            parsed.append(messageDelivered)

        logger.debug(f"[{__parser__}]:_parse_logs: "
                     f"got {len(json_logs['clicksPermitted'])} lines for 'clicksPermitted'",
                     extra={'frontend': str(self.frontend)})

        for clickPermitted in json_logs["clicksPermitted"]:
            clickPermitted['messageType'] = 'clicksPermitted'
            parsed.append(clickPermitted)

        logger.debug(f"[{__parser__}]:_parse_logs: "
                     f"got {len(json_logs['clicksBlocked'])} lines for 'clicksBlocked'",
                     extra={'frontend': str(self.frontend)})

        for clicksBlocked in json_logs["clicksBlocked"]:
            clicksBlocked['messageType'] = 'clicksBlocked'
            parsed.append(clicksBlocked)

        return time_string, parsed

    def _parse_timestamp(self, timestamp):
        try:
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
        try:
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S+00:00")
        except ValueError:
            pass
        try:
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            pass
        try:
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f+00:00")
        except ValueError:
            pass

        raise ProofpointTAPParseError("Couldn't parse time from '{}'".format(timestamp))

    def execute(self):
        error = ""
        currentTime = datetime.now(timezone.utc)
        fromTime = self.last_api_call
        parsed_lines = []

        try:
            # proofpoint API requires intervals of an hour max
            if currentTime - self.last_api_call < timedelta(hours=1):
                logger.debug(f"[{__parser__}]:execute: getting logs from {fromTime}",
                             extra={'frontend': str(self.frontend)})

                status, contents = self._get_logs(endpoint=self.proofpoint_tap_endpoint,
                                                  params={"sinceTime": fromTime.isoformat().replace("+00:00", "Z")})
                if status:
                    try:
                        time_string, parsed_lines = self._parse_logs(contents)
                        fromTime = self._parse_timestamp(time_string)
                    except ProofpointTAPParseError as e:
                        error = "parse error: {}".format(e)
                    except ProofpointTAPAPIError as e:
                        error = "API error: {}".format(e)
                else:
                    error += f"Could not get logs: {contents}"
            else:
                while True:
                    # do not go over current time
                    toTime = min(currentTime, fromTime + timedelta(hours=1))
                    try:
                        msg = f"getting logs from {fromTime} to {toTime}"
                        logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                        status, contents = self._get_logs(endpoint=self.proofpoint_tap_endpoint, params={"interval": "{}/{}".format(fromTime.isoformat().replace("+00:00", "Z"),toTime.isoformat().replace("+00:00", "Z"))})
                    except ProofpointTAPAPITooFarError:
                        # script didn't launch in a long time, so last_api_call as too far back
                        # now last_api_call has been updated to 12 hours ago so script can continue
                        fromTime = self.last_api_call
                        continue
                    except ProofpointTAPAPIError:
                        error += "APi error: exception while querying logs, stopping requests"
                        break

                    if status:
                        try:
                            time_string, new_lines = self._parse_logs(contents)
                            if new_lines is not None:
                                parsed_lines += new_lines
                            fromTime = self._parse_timestamp(time_string)
                        except ProofpointTAPParseError as e:
                            error += "parse error: {}\n".format(e)
                    else:
                        error += "{}\n".format(e)
                        break

                    fromTime = toTime

                    if not status or toTime == currentTime:
                        break
        
            if parsed_lines:
                msg = f"will write {len(parsed_lines)} lines"
                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                self.write_to_file([json_dumps(line) for line in parsed_lines])
            self.update_lock()

        except Exception as e:
            msg = f"Unknown error: {e}"
            logger.exception(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
        self.frontend.last_api_call = fromTime
        msg = f"last_api_call updated to {self.frontend.last_api_call}"
        logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        if error is not "":
            msg = f"errors while recovering logs:\n{error}"
            logger.error(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
