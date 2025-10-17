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

__author__ = "nlancon"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'PERCEPTION POINT X RAY API Parser'
__parser__ = 'PERCEPTION_POINT_X_RAY'

import json
import logging
from django.conf import settings
from django.utils import timezone, dateparse

from toolkit.api_parser.api_parser import ApiParser

from requests import Session, exceptions
from json import dumps, decoder

from datetime import datetime, timedelta

from toolkit.api_parser.perception_point_x_ray.scans import ScanMixin
from toolkit.api_parser.perception_point_x_ray.cases import CaseMixin

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class PerceptionPointXRayAPIError(Exception):
    pass


class PerceptionPointXRayParser(ApiParser, ScanMixin, CaseMixin):

    HEADERS = {
        "Accept": "application/json"
    }

    def __init__(self, data):
        super().__init__(data)

        self.logger = logger

        self.perception_point_x_ray_host = "https://" + data["perception_point_x_ray_host"].split("://")[-1].rstrip()
        self.token = data['perception_point_x_ray_token']
        self.perception_point_x_ray_organization_id = data['perception_point_x_ray_organization_id']

        self.session = None


    def _execute_query(self, url, query=None, timeout=10):
        retry = 1
        while retry <= 3 and not self.evt_stop.is_set():
            if self.session is None:
                self._connect()
            msg = f"call {url} with query {query} (retry: {retry})"
            logger.debug(f"[{__parser__}]:__execute_query: {msg}", extra={'frontend': str(self.frontend)})
            try:
                response = self.session.get(
                    url,
                    params=query,
                    timeout=timeout,
                    proxies=self.proxies,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                )
                response.raise_for_status()
                return response.json()
            except exceptions.Timeout:
                logger.warning(f"[{__parser__}]:__execute_query: TimeoutError: retry += 1 (waiting 10s)",
                             extra={'frontend': str(self.frontend)})
                retry += 1
                self.evt_stop.wait(10.0)
                continue
            except exceptions.HTTPError as err:
                if err.response is not None:
                    if err.response.status_code in (401, 403):
                        logger.error(f"[{__parser__}]:__execute_query: Received a 401/403,"
                                    " token is not (longer) valid!",
                            extra={'frontend': str(self.frontend)})
                        raise PerceptionPointXRayAPIError("Invalid token")
                    if err.response.status_code == 429:
                        logger.error(f"[{__parser__}]:__execute_query: Received a 429,"
                                    " stopping collector and waiting for next run",
                            extra={'frontend': str(self.frontend)})
                        raise PerceptionPointXRayAPIError("Rate limit reached")
                logger.error(f"[{__parser__}]:__execute_query: Unknown error at PerceptionPointXRay API Call URL:"
                             f" {url}: {err}", extra={'frontend': str(self.frontend)})
                retry += 1
                self.evt_stop.wait(10.0)
            except decoder.JSONDecodeError as err:
                logger.error(f"[{__parser__}]:__execute_query: Could not decode JSON from answer: {err}",
                            extra={'frontend': str(self.frontend)})
                raise PerceptionPointXRayAPIError("JSON decoding error")
        msg = f"Error at PerceptionPointXRay API Call URL: {url}: Unable to get a correct response"
        logger.error(f"[{__parser__}]:__execute_query: {msg}", extra={'frontend': str(self.frontend)})
        raise PerceptionPointXRayAPIError("No response")


    def _connect(self):
        if self.session is None:
            self.session = Session()
            self.session.headers.update(self.HEADERS)
            self.session.headers.update({"Authorization": f"Token {self.token}"})
        return True


    def test(self):
        try:
            if self.session is None:
                self._connect()

            since = timezone.now() - timedelta(hours=24)
            to = timezone.now()

            response, _, _, _ = self.get_scan_logs(since, to, self.SCAN_LOG_TYPES[0], None)

            return {
                "status": True,
                "data": response
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def execute(self):

        self.execute_cases()
        self.execute_scans()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
